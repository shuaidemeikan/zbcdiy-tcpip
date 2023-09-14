/**
 * 整个socket接口这一块有一些有趣的处理，我写在raw模块这里，因为raw本身有一些独特的处理
 * 1、在此前协议栈内部的模块，涉及到内存的分配，都是使用mblock来分配的，但是实际上这里不需要用mblock分配
 * 因为socket接口的所有模块都是用的exmsg来调用的，exmsg本身就会保证同一时间内只有一个线程可以执行这一块的代码
 * 所以这一块其实是单线程的，使用mblock反而会因为对锁的多余处理而影响效率
 * 但是使用mblock并不是完全不好的，如果不是用mblock，分配和释放等等操作都需要自己重写
 * socket结构比较灵活，重写也无可厚非，所以socket结构没有使用mblock来分配
 * 2、raw结构实质上是给sock结构加了几个字段，所以在初始化和调用的时候，其实可以直接把raw结构当做sock结构来处理
 */
#include "raw.h"
#include "debug.h"
#include "mblock.h"
#include "sock.h"
#include "pktbuf.h"
#include "ipv4.h"
#include "socket.h"

#define RAW_MAX_NR      10

static raw_t raw_tbl[RAW_MAX_NR];
static mblock_t raw_mblock;
static nlist_t raw_list;

#if DBG_DISP_ENABLED(DBG_RAW)
static void display_raw_list (void)
{
    plat_printf("---------- raw list ----------");

    nlist_node_t* node;
    int idx = 0;
    nlist_for_each(node, &raw_list)
    {
        raw_t* raw = (raw_t*)nlist_entry(node, sock_t, node);
        plat_printf("[%d]\n", idx++);
        dbg_dump_ip("   local:",&raw->base.local_ip);
        dbg_dump_ip("   remote:",&raw->base.remote_ip);
        plat_printf("\n");
    }
}
#else
#define display_raw_list()
#endif

/**
 * @brief raw模块初始化
 * @return net_err_t类型的返回值 
 */
net_err_t raw_init (void)
{
    dbg_info(DBG_RAW, "raw init");

    nlist_init(&raw_list);
    mblock_init(&raw_mblock, raw_tbl, sizeof(raw_t), RAW_MAX_NR, NLOCKER_NONE);
    dbg_info(DBG_RAW, "done");
    return NET_ERR_OK;
}

/**
 * @brief 利用源地址，目标地址，协议从raw结构的链表里找出来一个raw结构
 * @param src 
 * @param dest 
 * @param protocol 
 * @return raw_t* 
 */
static raw_t* sock_find (ipaddr_t* src, ipaddr_t* dest, int protocol)
{
    nlist_node_t* node;
    nlist_for_each(node, &raw_list)
    {
        raw_t* raw = (raw_t*)nlist_entry(node, sock_t, node);

        // 如果不为空，那就比较一下是否一致，下面是三个都是这样
        if (raw->base.protocol && (raw->base.protocol != protocol))
            continue;
        if (!ipaddr_is_any(&raw->base.local_ip) && !ipaddr_is_equal(&raw->base.local_ip, dest))
            continue;
        if (!ipaddr_is_any(&raw->base.remote_ip) && !ipaddr_is_equal(&raw->base.remote_ip, src))
            continue;
        
        return raw;
    }

    return (raw_t*)0;
}

/**
 * @brief raw类型的socket的发送函数
 * @param s sock
 * @param buf 待发送的内容
 * @param len 待发送的长度
 * @param flags 待发送的flags，其实用不到
 * @param dest 目标地址
 * @param dest_len 目标地址长度
 * @param result_len 具体发送了多少个字节
 * @return net_err_t类型
 */
static net_err_t raw_sendto (struct _sock_t* s, const void* buf, size_t len, int flags, const struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t * result_len)
{
    // 最终我们调用ipv4_out函数发送，所以地址需要ipaddrt类型
    ipaddr_t dest_ip;
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);

    // s内部的目标地址为空或者sock内部的目标地址要和实际发送的地址一致起码满足一条
    if (!ipaddr_is_any(&s->remote_ip) && !ipaddr_is_equal(&s->remote_ip, &dest_ip))
    {
        dbg_error(DBG_RAW, "dest is incorrect");
        return NET_ERR_PARAM;
    }

    // 发送
    pktbuf_t* pktbuf = pktbuf_alloc((int)len);
    if (!pktbuf)
    {
        dbg_error(DBG_SOCKET, "no buffer");
        return NET_ERR_MEM;
    }

    net_err_t err = pktbuf_write(pktbuf, (uint8_t*)buf, (int)len);
    if (err < 0)
    {
        dbg_error(DBG_RAW, "write pktbuf failed");
        goto end_send_to;
    }

    err = ipv4_out(s->protocol, &dest_ip, &s->local_ip, pktbuf);
    if (err < 0)
    {
        dbg_error(DBG_RAW, "sendto failed");
        goto end_send_to;
    }

    // 记得修改一下具体发送了多少字节的值
    *result_len = (ssize_t)len;
    return NET_ERR_OK;

end_send_to:
    pktbuf_free(pktbuf);
    return err;
}

/**
 * @brief raw类型的socket的接收函数
 * @param s sock
 * @param buf 用来存储接收到的内容的缓冲区
 * @param len 需要接收的长度
 * @param flags 待发送的flags，其实用不到
 * @param dest 目标地址
 * @param dest_len 目标地址长度
 * @param result_len 具体接收了多少个字节
 * @return net_err_t类型
 */
static net_err_t raw_recvfrom (struct _sock_t* s, void* buf, size_t len, int flags, struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t * result_len)
{
    raw_t* raw = (raw_t*)s;

    // 从raw的buf里移出来一个数据包，
    nlist_node_t * first = nlist_remove_first(&raw->recv_list);
    if (!first)
    {
        // 如果buf里没有数据，那么就说明协议栈内部还没有收到从目标机器发送的回包，返回一个需要等待的错误类型，让上层函数等待
        // 此时上层函数是属于sock模块的，sock模块依然属于协议栈内部，会占用工作线程，所以实际上等待的操作是在上层函数的上层函数里实现的
        dbg_error(DBG_RAW, "no packet");
        return NET_ERR_NEED_WAIT;
    }

    // 获得ip数据包的包头
    pktbuf_t* pktbuf = nlist_entry(first, pktbuf_t, node);
    ipv4_hdr_t* iphdr = (ipv4_hdr_t*)pktbuf_data(pktbuf);

    // 将ip数据包的源ip拷贝到dest中，以便上层函数可以知道是谁发过来的数据包
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    plat_memset(addr, 0, sizeof(struct x_sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = 0;
    plat_memcpy(&addr->sin_addr, &iphdr->src_ip, IPV4_ADDR_SIZE);

    // 最大大小是size，如果收到的数据包大小不大于size，则size为收到的数据包大小
    int size = (pktbuf->total_size > (int)len ? len : pktbuf->total_size);
    pktbuf_reset_acc(pktbuf);

    // 把buf拷贝到待拷贝区
    net_err_t err = pktbuf_read(pktbuf, buf, size);
    if(err < 0)
    {
        dbg_error(DBG_RAW, "read failed");
        return err;
    }

    // 释放收到的buf
    pktbuf_free(pktbuf);
    // 设置读取的大小
    *result_len = size;
    return NET_ERR_OK;
}

/**
 * @brief 关闭一个raw结构
 * @param sock 待关闭的sock结构
 * @return net_err_t 
 */
net_err_t raw_close (sock_t* sock)
{
    raw_t* raw = (raw_t*)sock;
    nlist_remove(&raw_list, &sock->node);

    nlist_node_t* node;
    while ((node = nlist_remove_first(&raw->recv_list)))
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(buf);
    }

    sock_uninit(sock);
    mblock_free(&raw_mblock, sock);

    display_raw_list();

    return NET_ERR_OK;

}

/**
 * 创建一个raw结构
 * @param str 字符串类型的地址
 * @return 转换成的32位数据
 */
sock_t* raw_create (int family, int protocol)
{
    // 创建用于raw操作的函数
    static const sock_ops_t raw_ops = {
        .sendto = raw_sendto,
        .recvfrom = raw_recvfrom,
        .close = raw_close,
        .setopt = sock_setopt,
        .connect = sock_connect,
        .recv = sock_recv,
        .send = sock_send,
    };

    // 申请一个rwa
    raw_t* raw = mblock_alloc(&raw_mblock, -1);
    if (!raw)
    {
        dbg_error(DBG_RAW, "no raw sock");
        return (sock_t*)0;
    }

    // 把这个raw结构当做socket结构初始化
    net_err_t err = sock_init((sock_t*)raw, family, protocol, &raw_ops);
    if (err < 0)
    {
        dbg_error(DBG_RAW, "create raw failed");
        mblock_free(&raw_mblock, raw);
        return (sock_t*)0;
    }

    nlist_init(&raw->recv_list);
    ((sock_t*)raw)->recv_wait = &raw->recv_wait;
    if (sock_wait_init(raw->base.recv_wait) < 0)
    {
        dbg_error(DBG_RAW, "create raw recv wait failed");
        goto create_failed;
    }

    nlist_insert_last(&raw_list, &raw->base.node);
    return (sock_t*)raw;

create_failed:
    sock_uninit(&raw->base);
    return (sock_t*)0;
}

/**
 * @brief 当协议栈内部接收到应该交给raw类型的socket来处理的数据包(例如icmp回应包，不认识的ipv4封装的数据包)时，会调用raw_in
 *        该函数会找到该数据包对应的raw结构，随后唤醒等待中的应用程序
 * @param buf 
 * @return ** net_err_t 
 */
net_err_t raw_in (pktbuf_t* buf)
{
    // 拿到ipv4的包头
    ipv4_hdr_t* iphdr = (ipv4_hdr_t*)pktbuf_data(buf);
    
    ipaddr_t src, dest;
    ipaddr_from_buf(&src, iphdr->src_ip);
    ipaddr_from_buf(&dest, iphdr->dest_ip);

    // 查找该数据包在raw表中对应的raw结构
    raw_t* raw = (raw_t*)sock_find(&src, &dest, iphdr->protocol);
    if (!raw)
    {
        dbg_warning(DBG_RAW, "no raw for this packet");
        return NET_ERR_UNREACH;
    }

    // 把数据包交给raw处理
    if (nlist_count(&raw->recv_list) < RAW_MAX_RECV)
    {
        // 先把数据包写到raw结构的buf里
        nlist_insert_first(&raw->recv_list, &buf->node);
        
        // 再唤醒一个等待中的线程，这个线程应该是应用程序在调用socket的recvfrom的时候等待的
        sock_wakeup((sock_t*)raw, SOCK_WAIT_READ, NET_ERR_OK);
    }else
        pktbuf_free(buf);

    return NET_ERR_OK;   
}