#include "arp.h"
#include "debug.h"
#include "mblock.h"

static arp_entry_t cache_tbl[ARP_CACHE_SIZE];       // arp可使用的系统中所有的内存
static mblock_t cache_mblock;                       // 用来分配上面的数据
static nlist_t cache_list;                           // arp链表

static net_err_t cache_init(void)
{
    nlist_init(&cache_list);

    net_err_t err = mblock_init(&cache_mblock, &cache_tbl, sizeof(arp_entry_t), ARP_CACHE_SIZE, NLOCKER_NONE);
    if (err < 0)
    {
        return err;
    }

    return NET_ERR_OK;
}

net_err_t arp_init (void)
{
    net_err_t err = cache_init();
    if (err < 0)
    {
        dbg_ERROR(DBG_ARP, "arp cache init failed.");
        return err;
    }
    return err;
}