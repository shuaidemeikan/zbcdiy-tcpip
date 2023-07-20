#include "ether.h"
#include "debug.h"
#include "netif.h"
#include "tools.h"
#include "protocol.h"

#if DBG_DISP_ENABLED(DBG_ETHER)

static void display_ether_pkt(char* title, ether_pkt_t* pkt, int total_size)
{
    ether_hdr_t* hdr = &pkt->hdr;

    plat_printf("------------- %s -------- \n", title);
    plat_printf("\t len: %d bytes\n", total_size);
    dbg_dump_hwaddr("\t src:", hdr->src, ETHER_HWA_SIZE);
    dbg_dump_hwaddr("\t dest:", hdr->dest, ETHER_HWA_SIZE);
    plat_printf("\ttype: %04x\n", x_ntohs(hdr->protocol));

    switch (x_ntohs(hdr->protocol))
    {
        case NET_PROTOCOL_ARP:
            plat_printf("arp\n");
            break;
        case NET_PROTOCOL_IPV4:
            plat_printf("IPV4\n");
            break;
        default:
            plat_printf("unknown\n");
            break;
    }
    plat_printf("\n");
}

#else
static void display_ether_pkt(char* title, ether_pkt_t* pkt, int total_size)
{
    return;
}
#endif 

net_err_t ether_open (struct _netif_t* netif)
{
    return NET_ERR_OK;
}

void ether_close (struct _netif_t* netif)
{

}
/**
 * 简单通过大小判断一下读进来的以太网数据帧是否合法
 * @param frame 被判断的以太网数据帧
 * @param total_size 该以太网数据帧的大小
 * @return net_err_t类型的返回值
 */
static net_err_t is_pkt_ok(ether_pkt_t* frame, int total_size)
{
    if (total_size > (sizeof(ether_hdr_t) + ETHER_MTU))
    {
        dbg_WARNING(DBG_ETHER, "frame size too big: %d", total_size);
        return NET_ERR_SIZE;
    }
    
    if (total_size < sizeof(ether_hdr_t))
    {
        dbg_WARNING(DBG_ETHER, "frame size too small: %d", total_size);
        return NET_ERR_SIZE;
    }
    return NET_ERR_OK;
}

/**
 * 简单通过大小判断一下读进来的以太网数据帧是否合法
 * @param frame 被判断的以太网数据帧
 * @param total_size 该以太网数据帧的大小
 * @return net_err_t类型的返回值
 */
net_err_t ether_in (struct _netif_t* netif, pktbuf_t* buf)
{
    dbg_info(DBG_ETHER, "ether in");
    ether_pkt_t* pkt = (ether_pkt_t*)pktbuf_data(buf);
    net_err_t err = is_pkt_ok(pkt, buf->total_size);
    if (err < 0)
    {
        dbg_WARNING(DBG_ETHER, "ether pkt error");
        return err;
    }

    display_ether_pkt("ether in", pkt, buf->total_size);
    pktbuf_free(buf);
    return NET_ERR_OK;
}
    
net_err_t ether_out (struct _netif_t* netif, ipaddr_t* dest, pktbuf_t* buf)
{
    if (ipaddr_is_equal(&netif->ipaddr, dest))
    {
        return ether_raw_out(netif, NET_PROTOCOL_IPV4, (const uint8_t*)netif->hwadder.addr, buf);
    }
    return NET_ERR_OK;
}

net_err_t ether_init(void)
{
    static const link_layer_t link_layer = {
        .type = NETIF_TYPE_ETHER,
        .open = ether_open,
        .close = ether_close,
        .in = ether_in,
        .out = ether_out
    };

    dbg_info(DBG_ETHER, "init ether");

    net_err_t err = netif_register_layer(NETIF_TYPE_ETHER, &link_layer);
    if (err < 0)
    {
        dbg_info(DBG_ETHER, "register error");
        return err;
    }

    dbg_info(DBG_ETHER, "done");
    return NET_ERR_OK;

}

/**
 * 返回一个广播地址
 * @return 广播地址
 */
const uint8_t* ether_broadcast_addr (void)
{
    static const uint8_t broadcast[] = {0xFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF};
    return broadcast;
}

/**
 * 以太网数据包发送前最后一步处理
 * @param netif 从那张网卡发送
 * @param protocol 以太网承载的上层协议
 * @param dest 目标mac地址
 * @param buf 发送的数据包
 * @return err类型的返回值
 */
net_err_t ether_raw_out (netif_t* netif, uint16_t protocol, const uint8_t* dest, pktbuf_t* buf)
{
    net_err_t err;
    
    // 先判断待发送的数据包是否符合最小以太网数据帧的标准，如果不符合，就要填充
    int size = pktbuf_total(buf);
    if (size < ETHER_DATA_MIN)
    {
        dbg_info(DBG_ETHER, "resize from %d to %d", size, ETHER_DATA_MIN);
        err = pktbuf_resize(buf, ETHER_DATA_MIN);
        if (err < 0)
        {
            dbg_ERROR(DBG_ETHER, "resize error");
            return err;
        }

        pktbuf_reset_acc(buf);
        pktbuf_seek(buf, size);
        pktbuf_fill(buf, 0, ETHER_DATA_MIN - size);
        size = ETHER_DATA_MIN;
    }

    // 给这个包的头部添加一些可用空间
    err = pktbuf_add_header(buf, sizeof(ether_hdr_t), 1);
    if (err < 0)
    {
        dbg_ERROR(DBG_ETHER, "add header error:%d", err);
        return NET_ERR_SIZE;
    }

    // 写头部
    ether_pkt_t* pkt = (ether_pkt_t*)pktbuf_data(buf);
    plat_memcpy(pkt->hdr.dest, dest, ETHER_HWA_SIZE);
    plat_memcpy(pkt->hdr.src, netif->hwadder.addr, ETHER_HWA_SIZE);
    pkt->hdr.protocol = x_htons(protocol);

    display_ether_pkt("ether out:", pkt, size);

    // 如果目的mac地址就是本网卡，那么直接丢到网卡的输入队列就ok了
    if (plat_memcmp(netif->hwadder.addr, dest, ETHER_HWA_SIZE) == 0)
        return netif_put_in(netif, buf, -1);
    else
    {
        err = netif_put_out(netif, buf, -1);
        if (err < 0)
        {
            dbg_WARNING(DBG_ETHER, "put pkt out failed.");
            return err;
        }

        return netif->ops->xmit(netif);
    }
}