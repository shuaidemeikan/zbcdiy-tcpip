#include "udp.h"
#include "mblock.h"
#include "debug.h"

static udp_t udp_tbl[UDP_MAX_NR];
static mblock_t udp_mblock;
static nlist_t udp_list;

net_err_t udp_init(void)
{
    dbg_info(DBG_UDP, "udp init.");

    mblock_init(&udp_mblock, udp_tbl, sizeof(udp_t), UDP_MAX_NR, NLOCKER_NONE);
    nlist_init(&udp_list);
    
    dbg_info(DBG_UDP, "udp init done.");
    return NET_ERR_OK;
}

sock_t* udp_create (int family, int protocol)
{
    // 创建用于udp操作的函数
    static const sock_ops_t udp_ops = {
        .setopt = sock_setopt,
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