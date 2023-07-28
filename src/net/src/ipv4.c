#include "ipv4.h"
#include "debug.h"
#include "tools.h"
#include "protocol.h"
#include "icmpv4.h"

static uint16_t packet_id = 0;

#if DBG_DISP_ENABLED(DBG_IP)
static void display_ip_pkt(ipv4_pkt_t* pkt)
{
    ipv4_hdr_t* ip_hdr = &pkt->hdr;
    plat_printf("--------------ip ---------------\n");
    plat_printf("    version: %d\n", ip_hdr->version);
    plat_printf("    header len: %d\n", ipv4_hdr_size(pkt));
    plat_printf("    total len: %d\n", ip_hdr->total_len);
    plat_printf("    id: %d\n", ip_hdr->id);
    plat_printf("    ttl: %d\n", ip_hdr->ttl);
    plat_printf("    protocol: %d\n", ip_hdr->protocol);
    plat_printf("    checksum: %d\n", ip_hdr->hdr_checksum);
    dbg_dump_ip_buf("     src ip:", ip_hdr->src_ip);   
    dbg_dump_ip_buf(" dest ip:", ip_hdr->dest_ip);
    plat_printf("\n--------------ip end ---------------\n");
}
#else
#define display_ip_pkt(a)
#endif

static inline void iphdr_ntohs (ipv4_pkt_t* pkt)
{
    pkt->hdr.total_len = x_ntohs(pkt->hdr.total_len);
    pkt->hdr.id = x_ntohs(pkt->hdr.id);
    pkt->hdr.frag_all = x_ntohs(pkt->hdr.frag_all);
}

static inline void iphdr_htons (ipv4_pkt_t* pkt)
{
    pkt->hdr.total_len = x_htons(pkt->hdr.total_len);
    pkt->hdr.id = x_htons(pkt->hdr.id);
    pkt->hdr.frag_all = x_htons(pkt->hdr.frag_all);
}

static net_err_t is_pkt_ok (ipv4_pkt_t* pkt, int size, netif_t* netif)
{
    // 判断版本号
    if (pkt->hdr.version != NET_VERSION_IPV4)
    {
        dbg_WARNING(DBG_IP, "invalid ip version");
        return NET_ERR_NOT_SUPPORT;
    }

    // 判断ip包头长度
    if (ipv4_hdr_size(pkt) < sizeof(ipv4_hdr_t))
    {
        dbg_WARNING(DBG_IP, "ipv4 header size error");
        return NET_ERR_SIZE;
    }

    // 判断整个数据包的长度，首先不能小于包头，其次不能大于总大小
    int total_size = x_ntohs(pkt->hdr.total_len);
    if ((total_size < sizeof(ipv4_hdr_t)) || (size < total_size))
    {
        dbg_WARNING(DBG_IP, "ipv4 packet size error");
        return NET_ERR_SIZE;
    }
    // 校验和检测
    if (pkt->hdr.hdr_checksum) 
    {
        uint16_t c = checksum16(pkt, ipv4_hdr_size(pkt), 0, 1);
        if (c != 0) 
        {
            dbg_WARNING(DBG_IP, "bad checksum");
            return NET_ERR_BROKEN;
        }
    }

    // 一切正常
    return NET_ERR_OK;
    
}

/**
 * IPV4的初始化函数，理论上可以不要
 * @return net_err错误类型
 */
net_err_t ipv4_init (void)
{
    dbg_info(DBG_IP, "init ip\n");

    dbg_info(DBG_IP, "done");
    return NET_ERR_OK;
}

/**
 * 判断一下接收到的数据包属于什么上层协议，直接丢给上层协议了，离开ip协议的最后一层函数
 * @param netif 收到数据包的网卡
 * @param buf 收到的数据包(已移除以太网包头，但是没移除ip包头)
 * @param scr_ip 数据包内的源地址
 * @param dest_ip 数据包内的目的地址
 * @return net_err错误类型
 */
net_err_t ip_normal_in(netif_t* netif, pktbuf_t* buf, ipaddr_t* src_ip, ipaddr_t* dest_ip)
{
    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    switch (pkt->hdr.protocol)
    {
    case NET_PROTOCOL_ICMPv4:
    {
        icmpv4_in(src_ip, &netif->ipaddr, buf);
        break;
    }
    case NET_PROTOCOL_UDP:
        iphdr_htons(pkt);
        icmpv4_out_unreach(src_ip, &netif->ipaddr, ICMPv4_UNREACH_PORT, buf);
        break;
    case NET_PROTOCOL_TCP:
        break;
    default:
        dbg_WARNING(DBG_IP, "unknown protocol");
        break;
    }

    pktbuf_free(buf);
    return NET_ERR_UNREACH;
}

/**
 * 收到ip数据包后第一层用来处理的函数
 * 设置一下包头的连续性，判断一下数据包的正确与否，是否是发给自己的，最后直接丢给ip_normal_in了
 * @param 待发送的arp表项
 * @return net_err错误类型
 */
net_err_t ipv4_in (netif_t* netif, pktbuf_t* buf)
{
    dbg_info(DBG_IP, "ip in\n");

    // 设置包头连续性
    net_err_t err = pktbuf_set_cont(buf, sizeof(ipv4_hdr_t));
    if (err < 0)
    {
        dbg_ERROR(DBG_IP, "ajust header failed, err = %d\n", err);
        return err;
    }

    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    err = is_pkt_ok(pkt, buf->total_size, netif);
    if (err != NET_ERR_OK)
    {
        dbg_WARNING(DBG_IP, "packet is broken");
        return err;
    }

    iphdr_ntohs(pkt);
    // 当ip数据包总体不足46字节时，会在包的后面补充一些字节让它到达46
    // 在对数据包进行处理前，需要把后面的一些字节移除
    err = pktbuf_resize(buf, pkt->hdr.total_len);

    // 判断一下目的ip是不是发给我这个网卡的，或者发的广播包我们也处理
    ipaddr_t dest_ip, src_ip;
    ipaddr_from_buf(&dest_ip, pkt->hdr.dest_ip);
    ipaddr_from_buf(&src_ip, pkt->hdr.src_ip);
    if (!ipaddr_is_match(&netif->ipaddr, &netif->netmask, &dest_ip))
    {
        dbg_WARNING(DBG_IP, "ipaddr not match");
        return NET_ERR_UNREACH;
    }

    // 解析ip包中承载的上层协议
    err = ip_normal_in(netif, buf, &src_ip, &dest_ip);

    
    return NET_ERR_OK;
}

/**
 * 把一个上层协议的包用ip封装好，然后发出去
 * @param protocol 上层协议
 * @param dest 目的地之
 * @param src 源地址
 * @param buf 待发送的数据包(还没添加ip包头)
 * @return net_err错误类型
 */
net_err_t ipv4_out(uint8_t protocol, ipaddr_t* dest, ipaddr_t* src, pktbuf_t* buf)
{
    dbg_info(DBG_IP, "send an ip pkt");
    
    net_err_t err = pktbuf_add_header(buf, sizeof(ipv4_hdr_t), 1);
    if (err < 0)
    {
        dbg_ERROR(DBG_IP, "add header failed");
        return NET_ERR_SIZE;
    }

    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    pkt->hdr.shdr_all = 0;
    pkt->hdr.version = NET_VERSION_IPV4;
    ipv4_set_hdr_size(pkt, sizeof(ipv4_hdr_t));
    pkt->hdr.total_len = buf->total_size;
    pkt->hdr.id = packet_id;
    pkt->hdr.frag_all = 0;
    pkt->hdr.ttl = NET_IP_DEFAULT_TTL;
    pkt->hdr.protocol = protocol;
    pkt->hdr.hdr_checksum = 0;
    ipaddr_to_buf(src, pkt->hdr.src_ip);
    ipaddr_to_buf(dest, pkt->hdr.dest_ip);
    
    // 填充完成
    iphdr_htons(pkt);
    pktbuf_reset_acc(buf);
    pkt->hdr.hdr_checksum = pktbuf_checksum16(buf, ipv4_hdr_size(pkt), 0, 1);
    display_ip_pkt(pkt);

    err = netif_out(netif_get_default(), dest, buf);
    if (err < 0)
    {
        dbg_WARNING(DBG_IP, "send ip packet");
        err;
    }
    return NET_ERR_OK;
}