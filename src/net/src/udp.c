#include "udp.h"
#include "mblock.h"
#include "debug.h"
#include "tools.h"
#include "socket.h"
#include "net_cfg.h"
#include "protocol.h"
#include "tools.h"

static udp_t udp_tbl[UDP_MAX_NR];
static mblock_t udp_mblock;
static nlist_t udp_list;

#if DBG_DISP_ENABLED(DBG_UDP)
static void display_udp_packet(udp_pkt_t * pkt) {
    plat_printf("UDP packet:\n");
    plat_printf("source Port:%d\n", pkt->hdr.src_port);
    plat_printf("dest Port: %d\n", pkt->hdr.dest_port);
    plat_printf("length: %d bytes\n", pkt->hdr.total_len);
    plat_printf("checksum:  %04x\n", pkt->hdr.check_sum);
}

static void display_udp_list (void)
{
    plat_printf("---------- udp list ----------");

    nlist_node_t* node;
    int idx = 0;
    nlist_for_each(node, &udp_list)
    {
        udp_t* udp = (udp_t*)nlist_entry(node, sock_t, node);
        plat_printf("[%d]\n", idx++);
        dbg_dump_ip("   local:",&udp->base.local_ip);
        dbg_dump_ip("   remote:",&udp->base.remote_ip);
        plat_printf("\n");
    }
}

#else

#define display_udp_packet(packet)
#define static void display_udp_list ()
#endif

net_err_t udp_init(void)
{
    dbg_info(DBG_UDP, "udp init.");

    mblock_init(&udp_mblock, udp_tbl, sizeof(udp_t), UDP_MAX_NR, NLOCKER_NONE);
    nlist_init(&udp_list);
    
    dbg_info(DBG_UDP, "udp init done.");
    return NET_ERR_OK;
}

static int is_port_used(int port)
{
    nlist_node_t* node;
    nlist_for_each(node, &udp_list)
    {
        sock_t* sock = (sock_t*)nlist_entry(node, sock_t, node);
        if (sock->local_port == port)
            return 1;
    }
    return 0;
}

static net_err_t alloc_port (sock_t* sock)
{
    static int search_index = NET_PORT_DYN_START;

    for (int i = search_index; i <= NET_PORT_DYN_END; i++)
    {
        if (!is_port_used(i))
        {
            sock->local_port = i;
            return NET_ERR_OK;
        }
    }
    return NET_ERR_NONE;
}

static udp_t* udp_find (ipaddr_t* src, uint16_t sport, ipaddr_t* dest, uint16_t dport)
{
    nlist_node_t* node;
    nlist_for_each(node, &udp_list)
    {
        sock_t* sock = (sock_t*)nlist_entry(node, sock_t, node);
        if (sock->local_port != sport)
            continue;

        if (!sock->remote_port && (sock->remote_port != dport))
            continue;

        if (!ipaddr_is_any(&sock->local_ip) && !ipaddr_is_equal(&sock->local_ip, src))
            continue;

        if (!ipaddr_is_any(&sock->remote_ip) && !ipaddr_is_equal(&sock->remote_ip, dest))
            continue;
        
        return (udp_t*)sock;
    }
    return (udp_t*)0;
}

static net_err_t is_pkt_ok(udp_pkt_t* pkt, int size)
{
    if ((size < sizeof(udp_pkt_t)) || (size < pkt->hdr.total_len))
    {
        dbg_error(DBG_UDP, "udp packet size incorrect: %d", size);
        return NET_ERR_BROKEN;
    }

    return NET_ERR_OK;
}

static net_err_t udp_sendto (struct _sock_t* s, const void* buf, size_t len, int flags, const struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t * result_len)
{
    ipaddr_t dest_ip;
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);
    uint16_t dport = x_ntohs(addr->sin_port);
    // s内部的目标地址为空或者sock内部的目标地址要和实际发送的地址一致起码满足一条
    if (!ipaddr_is_any(&s->remote_ip) && !ipaddr_is_equal(&s->remote_ip, &dest_ip))
    {
        dbg_error(DBG_UDP, "dest ip is incorrect");
        return NET_ERR_PARAM;
    }

    if (s->remote_port && (dport != s->remote_port))
    {
        dbg_error(DBG_UDP, "dest port is incorrect");
        return NET_ERR_PARAM;
    }

    if (!(s->local_port) && ((s->err = alloc_port(s)) < 0))
    {
        dbg_error(DBG_UDP, "no port avaliable.");
        return NET_ERR_NONE;
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
        dbg_error(DBG_UDP, "write pktbuf failed");
        goto end_send_to;
    }

    err = udp_out(&dest_ip, dport, &s->local_ip, s->local_port, pktbuf);
    if (err < 0)
    {
        dbg_error(DBG_UDP, "send to failed");
        return err;
    }

    // 记得修改一下具体发送了多少字节的值
    *result_len = (ssize_t)len;
    return NET_ERR_OK;

end_send_to:
    pktbuf_free(pktbuf);
    return err;
}



static net_err_t udp_recvfrom (struct _sock_t* s, void* buf, size_t len, int flags, struct x_sockaddr* dest, x_socklen_t dest_len, ssize_t * result_len)
{
    udp_t* udp = (udp_t*)s;

    // 从udp的buf里移出来一个数据包，
    nlist_node_t * first = nlist_remove_first(&udp->recv_list);
    if (!first)
    {
        // 如果buf里没有数据，那么就说明协议栈内部还没有收到从目标机器发送的回包，返回一个需要等待的错误类型，让上层函数等待
        // 此时上层函数是属于sock模块的，sock模块依然属于协议栈内部，会占用工作线程，所以实际上等待的操作是在上层函数的上层函数里实现的
        dbg_error(DBG_UDP, "no packet");
        return NET_ERR_NEED_WAIT;
    }

    // 获得ip数据包的包头
    pktbuf_t* pktbuf = nlist_entry(first, pktbuf_t, node);
    udp_from_t* from = (udp_from_t*)pktbuf_data(pktbuf);

    // 将ip数据包的源ip拷贝到dest中，以便上层函数可以知道是谁发过来的数据包
    struct x_sockaddr_in* addr = (struct x_sockaddr_in*)dest;
    plat_memset(addr, 0, sizeof(struct x_sockaddr_in));
    addr->sin_family = AF_INET;
    addr->sin_port = from->port;
    ipaddr_to_buf(&from->from, addr->sin_addr.addr_array);
    pktbuf_remove_header(pktbuf, sizeof(udp_from_t));

    // 最大大小是size，如果收到的数据包大小不大于size，则size为收到的数据包大小
    int size = (pktbuf->total_size > (int)len ? len : pktbuf->total_size);
    pktbuf_reset_acc(pktbuf);
    
    // 把buf拷贝到待拷贝区
    net_err_t err = pktbuf_read(pktbuf, buf, size);
    if(err < 0)
    {
        dbg_error(DBG_UDP, "read failed");
        return err;
    }

    // 释放收到的buf
    pktbuf_free(pktbuf);
    // 设置读取的大小
    *result_len = size;
    return NET_ERR_OK;
}

net_err_t udp_close (sock_t* sock)
{
    udp_t* udp = (udp_t*)sock;
    nlist_remove(&udp_list, &sock->node);

    nlist_node_t* node;
    while ((node = nlist_remove_first(&udp->recv_list)))
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(buf);
    }

    sock_uninit(sock);
    mblock_free(&udp_mblock, sock);

    display_udp_list();

    return NET_ERR_OK;

}

net_err_t udp_connect (struct _sock_t* s, const struct x_sockaddr* dest, x_socklen_t dest_len)
{
    sock_connect(s, dest, dest_len);
    return NET_ERR_OK;
}

sock_t* udp_create (int family, int protocol)
{
    // 创建用于udp操作的函数
    static const sock_ops_t udp_ops = {
        .setopt = sock_setopt,
        .sendto = udp_sendto,
        .recvfrom = udp_recvfrom,
        .close = udp_close,
        .connect = udp_connect,
        .send = sock_send,
    };

    // 申请一个udp结构
    udp_t* udp = mblock_alloc(&udp_mblock, -1);
    if (!udp)
    {
        dbg_error(DBG_UDP, "no udp sock");
        return (sock_t*)0;
    }

    // 把这个udp结构当做socket结构初始化
    net_err_t err = sock_init((sock_t*)udp, family, protocol, &udp_ops);
    if (err < 0)
    {
        dbg_error(DBG_UDP, "create udp failed");
        mblock_free(&udp_mblock, udp);
        return (sock_t*)0;
    }

    nlist_init(&udp->recv_list);
    ((sock_t*)udp)->recv_wait = &udp->recv_wait;
    if (sock_wait_init(udp->base.recv_wait) < 0)
    {
        dbg_error(DBG_UDP, "create udp recv wait failed");
        goto create_failed;
    }

    nlist_insert_last(&udp_list, &udp->base.node);
    return (sock_t*)udp;

create_failed:
    sock_uninit(&udp->base);
    return (sock_t*)0;
}

net_err_t udp_out (ipaddr_t* dest, uint16_t dport, ipaddr_t* src, uint16_t sport, pktbuf_t* buf)
{
    dbg_info(DBG_UDP, "send an udp packet");

    // src地址为空时，查找路由表获得出口网卡的ip以计算伪首部的校验和
    if (!src || ipaddr_is_any(src))
    {
        rentry_t* rt = rt_find(dest);
        if (!rt)
        {
            dbg_dump_ip("no route to dest", dest);
            return NET_ERR_UNREACH;
        }

        src = &rt->netif->ipaddr;
    } 

    net_err_t err = pktbuf_add_header(buf, sizeof(udp_hdr_t), 1);
    if (err < 0)
    {
        dbg_error(DBG_UDP, "udp add header failed");
        return err;
    }

    udp_pkt_t * udp = (udp_pkt_t*)pktbuf_data(buf);
    udp->hdr.src_port = htons(sport);
    udp->hdr.dest_port = htons(dport);
    udp->hdr.total_len = htons(pktbuf_total(buf));
    udp->hdr.check_sum = 0;
    udp->hdr.check_sum = checksum_peso(src->a_addr, dest->a_addr, NET_PROTOCOL_UDP, buf);

    err = ipv4_out(IPPROTO_UDP, dest, src, buf);
    if (err < 0) {
        dbg_error(DBG_UDP, "udp out error, err = %d", err);
        return err;
    }

    return err;
}

net_err_t udp_in (pktbuf_t* buf, ipaddr_t* src, ipaddr_t* dest)
{
    int iphdr_size = ipv4_hdr_size((ipv4_pkt_t*)pktbuf_data(buf));
    
    net_err_t err = pktbuf_set_cont(buf, iphdr_size);
    if (err < 0)
    {
        dbg_error(DBG_UDP, "udp set cont failed");
        return err;
    }

    udp_pkt_t* udp_pkt = (udp_pkt_t*)(pktbuf_data(buf) + sizeof(ipv4_hdr_t));
    uint16_t src_port = x_ntohs(udp_pkt->hdr.dest_port);          // src指解析后本地的地址
    uint16_t dest_port = x_ntohs(udp_pkt->hdr.src_port);         // dest指解析后远端的地址

    udp_t* udp = (udp_t*)udp_find(dest, src_port, src, dest_port);
    if (!udp)
    {
        dbg_error(DBG_UDP, "no udp sock for packet");
        return NET_ERR_UNREACH;
    }

    pktbuf_remove_header(buf, iphdr_size);
    udp_pkt = (udp_pkt_t*)pktbuf_data(buf);
    if (udp_pkt->hdr.check_sum)
    {
        pktbuf_reset_acc(buf);
        if (checksum_peso(dest->a_addr, src->a_addr, NET_PROTOCOL_UDP, buf))
        {
            dbg_warning(DBG_UDP, "udp checksum error");
            return NET_ERR_CHECKSUM;
        }
    }   

    udp_pkt->hdr.src_port = x_ntohs(udp_pkt->hdr.src_port);
    udp_pkt->hdr.dest_port = x_ntohs(udp_pkt->hdr.dest_port);
    udp_pkt->hdr.total_len = x_ntohs(udp_pkt->hdr.total_len);
    if (err = is_pkt_ok(udp_pkt, buf->total_size) < 0)
    {
        dbg_error(DBG_UDP, "udp pkt check failed");
        return err;
    }
    display_udp_packet(udp_pkt); 

    pktbuf_remove_header(buf, (int)(sizeof(udp_hdr_t) - sizeof(udp_from_t)));
    udp_from_t* from = (udp_from_t*)pktbuf_data(buf);
    from->port = dest_port;
    ipaddr_copy(&from->from, src);

    if (nlist_count(&udp->recv_list) < UDP_MAX_RECV)
    {
        nlist_insert_last(&udp->recv_list, &buf->node);
        sock_wakeup((sock_t*)udp, SOCK_WAIT_READ, NET_ERR_OK);
    }else
    {
        dbg_warning(DBG_UDP, "udp recv list full");
        pktbuf_free(buf);
    }

    return NET_ERR_OK;
}