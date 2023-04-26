#include "loop.h"
#include "debug.h"

static net_err_t loop_open(struct _netif_t* netif, void* data)
{
    netif->type = NETIF_TYPE_LOOP;
    return NET_ERR_OK;
}

static void loop_close(struct _netif_t* netif)
{
    return;
}

static net_err_t loop_xmit(struct _netif_t* netif)
{
    pktbuf_t* pktbuf = netif_get_out(netif, -1);
    if (pktbuf)
    {
        net_err_t err = netif_put_in(netif, pktbuf, -1);
        if (err < 0)
        {
            pktbuf_free(pktbuf);
            return err;
        }
    }
    
    return NET_ERR_OK;
}

static const netif_ops_t loop_ops = {
    .open = loop_open,
    .close = loop_close,
    .xmit = loop_xmit,
};

/**
 * 本地环回网卡的初始化
 * @return err类型的返回值
 */
net_err_t loop_init (void)
{
    dbg_info(DBG_NETIF, "init loop");
    // 拿到一个网卡结构体
    netif_t* netif = netif_open("loop", &loop_ops, (void*)0);
    if (!netif)
    {
        dbg_ERROR(DBG_NETIF, "open loop err");
        return NET_ERR_NONE;
    }
    // 用于初始化网卡结构体的ip和掩码
    ipaddr_t ip, mask;
    ipaddr_from_str(&ip, "127.0.0.1");
    ipaddr_from_str(&mask, "255.0.0.0");
    netif_set_addr(netif, &ip, &mask, (ipaddr_t*)0);

    // 激活网卡
    netif_set_active(netif);
    
    pktbuf_t* buf = pktbuf_alloc(100);
    netif_out(netif, (ipaddr_t*)0, buf);

    netif_set_deactive(netif);
    netif_close(netif);
    dbg_info(DBG_NETIF, "loop init done");
    return NET_ERR_OK;
}