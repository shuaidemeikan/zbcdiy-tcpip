#include "tcp.h"
#include "debug.h"
#include "mblock.h"
#include "tcp_state.h"
#include "tools.h"
#include "tcp_out.h"
#include "time.h"

static tcp_t tcp_tbl[TCP_MAX_NR];
static mblock_t tcp_mblock;
static nlist_t tcp_list;

#if DBG_DISP_ENABLED(DBG_TCP)
void tcp_show_info (char * msg, tcp_t * tcp) {
    plat_printf("%s\n", msg);
    plat_printf("    local port: %u, remote port: %u\n", tcp->base.local_port, tcp->base.remote_port);
}

void tcp_display_pkt (char * msg, tcp_hdr_t * tcp_hdr, pktbuf_t * buf) {
    plat_printf("%s\n", msg);
    plat_printf("    sport: %u, dport: %u\n", tcp_hdr->sport, tcp_hdr->dport);
    plat_printf("    seq: %u, ack: %u, win: %d\n", tcp_hdr->seq, tcp_hdr->ack, tcp_hdr->win);
    plat_printf("    flags:");
    if (tcp_hdr->f_syn) {
        plat_printf(" syn");
    }
    if (tcp_hdr->f_rst) {
        plat_printf(" rst");
    }
    if (tcp_hdr->f_ack) {
        plat_printf(" ack");
    }
    if (tcp_hdr->f_psh) {
        plat_printf(" push");
    }
    if (tcp_hdr->f_fin) {
        plat_printf(" fin");
    }

    plat_printf("\n    len=%d", buf->total_size - tcp_hdr_size(tcp_hdr));
    plat_printf("\n");
}

void tcp_show_list (void) {
    char idbuf[10];
    int i = 0;

    plat_printf("-------- tcp list -----\n");

    nlist_node_t * node;
    nlist_for_each(node, &tcp_list) {
        tcp_t * tcp = (tcp_t *)nlist_entry(node, sock_t, node);

        plat_memset(idbuf, 0, sizeof(idbuf));
        plat_printf(idbuf, "%d:", i++);
        tcp_show_info(idbuf, tcp);
    }
}
#endif

void tcp_free(tcp_t* tcp)
{
    // 先释放sock内的锁结构
    sock_wait_destory(&tcp->conn.wait);
    sock_wait_destory(&tcp->snd.wait);
    sock_wait_destory(&tcp->rcv.wait);

    tcp->state = TCP_STATE_FREE;
    nlist_remove(&tcp_list, &tcp->base.node);
    mblock_free(&tcp_mblock, tcp);
}

net_err_t tcp_abort (tcp_t* tcp, int err)
{
    tcp_set_state(tcp, TCP_STATE_CLOSED);
    sock_wakeup(&tcp->base, SOCK_WAIT_ALL, err);        // 把该tcp上在等待的线程全部唤醒，让他们不要再等了，直接销毁
    return NET_ERR_OK;
}

tcp_t* tcp_find(ipaddr_t* dest, uint16_t dport, ipaddr_t* src, uint16_t sport)
{
    nlist_node_t* node;
    nlist_for_each(node, &tcp_list)
    {
        sock_t* sock = (sock_t*)nlist_entry(node, sock_t, node);
        if (ipaddr_is_any(&sock->local_ip) && !ipaddr_is_equal(&sock->local_ip, dest))
            continue;
        if (!ipaddr_is_equal(&sock->remote_ip, src))
            continue;
        if (sock->local_port != dport && sock->remote_port != sport)
            continue;
        return (tcp_t*)sock;
    }
    return (tcp_t*)0;
}

// static int tcp_alloc_port(void)
// {
//     static int port = 1024;
//     for (; port < 65535; port++)
//     {
//         nlist_node_t * node;
//         nlist_for_each(node, &tcp_list)
//         {
//             tcp_t * tcp = (tcp_t *)nlist_entry(node, sock_t, node);
//             if (tcp->base.remote_port == port)
//                 port++;
//             else
//             {
//                 port++;
//                 return port;
//             }
//         }
//     }
//     return -1;
// }

static int tcp_alloc_port(void)
{
    int count = 0;
    while (count < 1000)
    {
        srand((unsigned int)time(NULL));
	    int port = rand() % (1025 - 65534 + 1) + 65534;
        nlist_node_t * node;
        nlist_for_each(node, &tcp_list)
        {
            tcp_t * tcp = (tcp_t *)nlist_entry(node, sock_t, node);
            if (tcp->base.remote_port != port)
                return port;
        }
        count++;
    }
    return -1;
}

net_err_t tcp_init(void)
{
    dbg_info(DBG_TCP, "tcp init.");

    mblock_init(&tcp_mblock, tcp_tbl, sizeof(tcp_t), TCP_MAX_NR, NLOCKER_NONE);
    nlist_init(&tcp_list);
    
    dbg_info(DBG_TCP, "tcp init done.");
    return NET_ERR_OK;
}

tcp_t* tcp_get_free(int wait)
{
    tcp_t* tcp = (tcp_t*)mblock_alloc(&tcp_mblock, wait);
    if (!tcp)
    {
        dbg_error(DBG_TCP, "tcp get free failed.");
        return (tcp_t*)0;
    }
    return tcp;
}

static uint32_t tcp_get_iss(void)
{
    static uint32_t iss = 0;
    return ++iss;
}

static net_err_t tcp_init_connect (tcp_t* tcp)
{
    tcp_buf_init(&tcp->snd.buf, tcp->snd.data, TCP_SBUF_SIZE);
    tcp->snd.iss = tcp_get_iss();
    tcp->snd.una = tcp->snd.nxt = tcp->snd.iss;
    
    tcp->rcv.nxt = 0;
    return NET_ERR_OK;
}

net_err_t tcp_connect (struct _sock_t* s, const struct x_sockaddr* dest, x_socklen_t dest_len)
{
    tcp_t* tcp = (tcp_t*)s;
    if (tcp->state != TCP_STATE_CLOSED)
    {
        dbg_error(DBG_TCP, "tcp connect failed, state is not closed.");
        return NET_ERR_STATE;
    }

    const struct x_sockaddr_in* addr = (const struct x_sockaddr_in*)dest;
    ipaddr_from_buf(&s->remote_ip, (uint8_t*)&addr->sin_addr.s_addr);
    s->remote_port = x_ntohs(addr->sin_port);

    if (s->local_port == NET_PORT_EMPTY)
    {
        int port = tcp_alloc_port();
        if (port == -1)
        {
            dbg_error(DBG_TCP, "tcp_alloc_port failed.");
            return NET_ERR_NONE; 
        }
        s->local_port = port;
    }

    if (ipaddr_is_any(&s->local_ip)) {
        // 检查路径，看看是否能够到达目的地。不能达到返回错误
        rentry_t * rt = rt_find(&s->remote_ip);
        if (rt == (rentry_t*)0) {
            dbg_error(DBG_TCP, "no route to dest");
            return NET_ERR_UNREACH;
        }
        ipaddr_copy(&s->local_ip, &rt->netif->ipaddr);
    }

    net_err_t err;
    if (err = tcp_init_connect((tcp_t*)s) < 0)
    {
        dbg_error(DBG_TCP, "tcp_init_connect failed.");
        return err;
    }

    if ((err = tcp_send_syn((tcp_t*)s)) < 0)
    {
        dbg_error(DBG_TCP, "send syn failed");
        return err;
    }

    tcp_set_state((tcp_t*)s, TCP_STATE_SYN_SENT);
    return NET_ERR_NEED_WAIT;
}

net_err_t tcp_close (struct _sock_t* s)
{
    tcp_t* tcp = (tcp_t*)s;
    dbg_info(DBG_TCP, "tcp_close");
    
    switch (tcp->state)
    {
    case TCP_STATE_CLOSED:
        dbg_info(DBG_TCP, "tcp already closed");
        tcp_free(tcp);
        return NET_ERR_OK;

    case TCP_STATE_SYN_RECVD:
    case TCP_STATE_SYN_SENT:
        tcp_abort(tcp, NET_ERR_CLOSE);
        tcp_free(tcp);
        return NET_ERR_OK;
    
    case TCP_STATE_ESTABLISHED:
        tcp_send_fin(tcp);
        tcp_set_state(tcp, TCP_STATE_FIN_WAIT_1);
        return NET_ERR_NEED_WAIT;

    case TCP_STATE_CLOSE_WAIT:
        tcp_send_fin(tcp); 
        tcp_set_state(tcp, TCP_STATE_LAST_ACK);
        return NET_ERR_NEED_WAIT;
    
    default:
        dbg_error(DBG_TCP, "tcp_close: unknown state");
        return NET_ERR_UNREACH;
        break;
    }

    return NET_ERR_OK;
}

net_err_t tcp_send (struct _sock_t* s, const void* buf, size_t len, int flags, ssize_t* result_len)
{
    tcp_t* tcp = (tcp_t*)s;

    switch (tcp->state)
    {
    case TCP_STATE_CLOSED:
        dbg_error(DBG_TCP, "tcp_send: tcp is closed");
        return NET_ERR_CLOSE;
        break;
    case TCP_STATE_FIN_WAIT_1:
    case TCP_STATE_FIN_WAIT_2:
    case TCP_STATE_CLOSING:
    case TCP_STATE_TIME_WAIT:
    case TCP_STATE_LAST_ACK:
        dbg_error(DBG_TCP, "tcp_send: tcp state does not support sending");
        return NET_ERR_CLOSE;
    case TCP_STATE_ESTABLISHED:
    case TCP_STATE_CLOSE_WAIT:
        break;
    case TCP_STATE_LISTEN:
    case TCP_STATE_SYN_RECVD:
    case TCP_STATE_SYN_SENT:
        dbg_error(DBG_TCP, "tcp_send: The tcp connection is not completed ");
        return NET_ERR_STATE;

    default:
        dbg_error(DBG_TCP, "tcp_send: tcp state is unkown");
        return NET_ERR_STATE;
    }

    int size = tcp_write_sndbuf(tcp, (uint8_t*)buf, len);
    if (size <= 0)
    {
        *result_len = 0;
        return NET_ERR_NEED_WAIT;
    }else
        *result_len = size;

    tcp_transmit(tcp);

    return NET_ERR_OK;
}

tcp_t* tcp_alloc(int tmo, int family, int protocol)
{
    static const sock_ops_t tcp_ops = {
        .connect = tcp_connect,
        .close = tcp_close,
        .send = tcp_send,
    };

    tcp_t* tcp = tcp_get_free(tmo);
    if (!tcp)
    {
        dbg_error(DBG_TCP, "tcp alloc failed.");
        return (tcp_t*)0;
    }
    plat_memset(tcp, 0, sizeof(tcp_t));

    net_err_t err = sock_init(&tcp->base, family, protocol, &tcp_ops);
    if (err < 0)
    {
        dbg_error(DBG_TCP, "sock init failed.");
        return (tcp_t*)0;
    }

    if (sock_wait_init(&tcp->conn.wait) < 0)
    {
        dbg_error(DBG_TCP, "sock wait init failed.");
        goto alloc_failed;
    }
    tcp->base.conn_wait = &tcp->conn.wait;

    if (sock_wait_init(&tcp->snd.wait) < 0)
    {
        dbg_error(DBG_TCP, "sock wait init failed.");
        goto alloc_failed;
    }
    tcp->base.send_wait = &tcp->snd.wait;

    if (sock_wait_init(&tcp->rcv.wait) < 0)
    {
        dbg_error(DBG_TCP, "sock wait init failed.");
        goto alloc_failed;
    }
    tcp->base.recv_wait = &tcp->rcv.wait;

    tcp_set_state(tcp, TCP_STATE_CLOSED);

    return tcp;

alloc_failed:
    if (tcp->base.conn_wait)
        sock_wait_destory(tcp->base.conn_wait);
    if (tcp->base.send_wait)
        sock_wait_destory(tcp->base.send_wait);
    if (tcp->base.recv_wait)
        sock_wait_destory(tcp->base.recv_wait);
    
    mblock_free(&tcp_mblock, tcp);
    return (tcp_t*)0;
}

static inline void tcp_insert(tcp_t* tcp)
{
    nlist_insert_last(&tcp_list, &tcp->base.node);
}

sock_t* tcp_create (int family, int protocol)
{
    tcp_t* tcp = tcp_alloc(1, family, protocol);
    if (!tcp)
    {
        dbg_error(DBG_TCP, "alloc tcp failed.");
        return (sock_t*)0;
    }

    tcp_insert(tcp);
    return (sock_t*)tcp;
}