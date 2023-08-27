#include "raw.h"
#include "debug.h"
#include "mblock.h"
#include "sock.h"

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

sock_t* raw_create (int family, int protocol)
{
    static const sock_opt_t raw_ops = {
        .sendto = raw_create,
    };
    raw_t* raw = mblock_alloc(&raw_mblock, -1);
    if (!raw)
    {
        dbg_error(DBG_RAW, "no raw sock");
        return (sock_t*)0;
    }

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