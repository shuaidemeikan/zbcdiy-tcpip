#include "tcp.h"
#include "debug.h"
#include "mblock.h"

static tcp_t tcp_tbl[TCP_MAX_NR];
static mblock_t tcp_mblock;
static nlist_t tcp_list;


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

tcp_t* tcp_alloc(int tmo, int family, int protocol)
{
    static const sock_ops_t tcp_ops;

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

    return tcp;
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