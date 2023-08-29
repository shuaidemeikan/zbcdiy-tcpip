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

net_err_t raw_init (void)
{
    dbg_info(DBG_RAW, "raw init");

    nlist_init(&raw_list);
    mblock_init(&raw_mblock, raw_tbl, sizeof(raw_t), RAW_MAX_NR, NLOCKER_NONE);
    dbg_info(DBG_RAW, "done");
    return NET_ERR_OK;
}

/**
 * raw类型的socket的发送函数
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
    // 目标地址不能为空
    if (!ipaddr_is_any(&s->remote_ip))
    {
        dbg_error(DBG_RAW, "dest is incorrect");
        return NET_ERR_PARAM;
    }
    // 最终我们调用ipv4_out函数发送，所以地址需要ipaddrt类型
    ipaddr_t dest_ip;
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);
    // sock内部的目标地址要和实际发送的地址一致
    if (!ipaddr_is_equal(&s->remote_ip, &dest_ip))
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

    err = ipv4_out(s->protocol, &dest_ip, &netif_get_default()->ipaddr, pktbuf);
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
 * 创建一个raw结构
 * @param str 字符串类型的地址
 * @return 转换成的32位数据
 */
sock_t* raw_create (int family, int protocol)
{
    // 创建用于raw操作的函数
    static const sock_opt_t raw_ops = {
        .sendto = raw_sendto,
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
    nlist_insert_last(&raw_list, &raw->base.node);
    return (sock_t*)raw;
}

