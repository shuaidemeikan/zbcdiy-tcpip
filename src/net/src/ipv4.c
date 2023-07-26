#include "ipv4.h"
#include "debug.h"
#include "tools.h"

static void iphdr_ntohs (ipv4_pkt_t* pkt)
{
    pkt->hdr.total_len = x_ntohs(pkt->hdr.total_len);
    pkt->hdr.id = x_ntohs(pkt->hdr.id);
    pkt->hdr.frag_all = x_ntohs(pkt->hdr.frag_all);
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

net_err_t ipv4_init (void)
{
    dbg_info(DBG_IP, "init ip\n");

    dbg_info(DBG_IP, "done");
    return NET_ERR_OK;
}

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

    pktbuf_free(buf);
    return NET_ERR_OK;
}