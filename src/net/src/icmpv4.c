#include "icmpv4.h"
#include "debug.h"
#include "protocol.h"
#include "raw.h"

net_err_t icmpv4_init (void)
{
    dbg_info(DBG_ICMPv4, "init icmp");
    dbg_info(DBG_ICMPv4, "done");

    return NET_ERR_OK;
}

/**
 * 将一个icmp的数据包发送出去，发送前的最后一步，包头大多已经填好，只要计算一下校验和就可以了
 * @param dest 目的地址
 * @param src 源地址
 * @param buf 待发送的数据包(icmp包头字段剩一个checksum没填)
 * @return net_err错误类型
 */
static net_err_t icmpv4_out(ipaddr_t* dest, ipaddr_t* src, pktbuf_t* buf)
{
    icmpv4_pkt_t* pkt = (icmpv4_pkt_t*)pktbuf_data(buf);

    pktbuf_reset_acc(buf);
    pkt->hdr.checksum16 = pktbuf_checksum16(buf, buf->total_size, 0, 1);

    return ipv4_out(NET_PROTOCOL_ICMPv4, dest, src, buf);
}

/**
 * 准备发送一个icmp数据包，包头还没填，这个函数主要是填包头的一些字段
 * @param dest 目的地址
 * @param src 源地址
 * @param buf 待发送的数据包(icmp包头字段一个没填)
 * @return net_err错误类型
 */
static net_err_t icmpv4_echo_reply(ipaddr_t* dest, ipaddr_t* src, pktbuf_t* buf)
{
    icmpv4_pkt_t* pkt = (icmpv4_pkt_t*)pktbuf_data(buf);

    pkt->hdr.type = ICMPv4_ECHO_REPLY;
    // 在这里需要先填一下checksum，因为后面计算checksum是默认这个字段为0的
    pkt->hdr.checksum16 = 0;
    return icmpv4_out(dest, src, buf);

}

static net_err_t is_pkt_ok(icmpv4_pkt_t* pkt, int size, pktbuf_t* buf)
{
    if (size <= sizeof(ipv4_hdr_t))
    {
        dbg_WARNING(DBG_ICMPv4, "size error");
        return NET_ERR_SIZE;
    }

    uint16_t checksum = pktbuf_checksum16(buf, size, 0, 1);
    if (checksum != 0)
    {
        dbg_WARNING(DBG_ICMPv4, "bad checksum");
        return NET_ERR_BROKEN;
    }
    return NET_ERR_OK;
}

/**
 * icmp输入处理函数，由ip_normal_in调用
 * @param src_ip 源地址
 * @param netif_ip 接收到该包的网卡地址
 * @param buf 接收到的包(没有移除ip包头)
 * @return net_err错误类型
 */
net_err_t icmpv4_in (ipaddr_t* src_ip, ipaddr_t* netif_ip, pktbuf_t* buf)
{
    dbg_info(DBG_ICMPv4, "icmpv4 in");

    ipv4_pkt_t* ip_pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    int iphdr_size = ipv4_hdr_size(ip_pkt);

    net_err_t err = pktbuf_set_cont(buf, iphdr_size + sizeof(icmpv4_hdr_t));
    if (err < 0)
    {
        dbg_ERROR(DBG_IP, "set icmp cont failed");
        return err;
    }

    ip_pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    

    icmpv4_pkt_t* icmp_pkt = (icmpv4_pkt_t*)(pktbuf_data(buf) + iphdr_size);

    pktbuf_seek(buf, iphdr_size);

    if (err = is_pkt_ok(icmp_pkt, buf->total_size, buf) < 0)
    {
        dbg_WARNING(DBG_ICMPv4, "icmp pkt error");
        return err;
    }

    switch (icmp_pkt->hdr.type)
    {
    case ICMPv4_ECHO_REQUEST:
    {
        err = pktbuf_remove_header(buf, iphdr_size);
        if (err < 0)
        {
            dbg_ERROR(DBG_IP, "remove ip header failed.");
            return NET_ERR_SIZE;
        }
        pktbuf_reset_acc(buf);

        return icmpv4_echo_reply(src_ip, netif_ip, buf);
    }
    
    case 3:
    {
        pktbuf_free(buf);
        return NET_ERR_OK;
    }

    // 不是icmp请求包，那就是回应包，收到回应包就丢给raw结构
    default:
    {   
        err = raw_in(buf);
        if (err < 0)
        {
            dbg_error(DBG_ICMPv4, "raw in failed");
            return err;
        }
        return NET_ERR_OK;
    }
    }
}

/**
 * 利用icmp发送一个端口不可达的报文
 * 该报文发送时，需要将收到的ip包从ip包头往后576个字节拷贝到待发送包的尾部
 * @param dest_ip 目的地址
 * @param src 源地址
 * @param code 编号
 * @param ip_buf 收到的端口不可达的udp包
 * @return net_err错误类型
 */
net_err_t icmpv4_out_unreach (ipaddr_t* dest_ip, ipaddr_t* src, uint8_t code, pktbuf_t* ip_buf)
{
    int copy_size = ipv4_hdr_size((ipv4_pkt_t*)pktbuf_data(ip_buf)) + 576;
    if (copy_size > ip_buf->total_size)
        copy_size = ip_buf->total_size;
    
    // 新数据包的大小为尾部填充的大小+icmp包头的大小
    pktbuf_t* new_buf = pktbuf_alloc(copy_size + sizeof(icmpv4_hdr_t) + 4);
    if (!new_buf)
    {
        dbg_WARNING(DBG_ICMPv4, "alloc buf failed");
        return NET_ERR_NONE;
    }

    icmpv4_pkt_t* pkt = (icmpv4_pkt_t*)pktbuf_data(new_buf);
    pkt->hdr.type = ICMPv4_UNREACH;
    pkt->hdr.code = code;
    pkt->hdr.checksum16 = 0;
    pkt->reverse = 0;

    pktbuf_reset_acc(ip_buf);
    pktbuf_seek(new_buf, sizeof(icmpv4_hdr_t) + 4);
    net_err_t err= pktbuf_copy(new_buf, ip_buf, copy_size);
    if (err < 0)
    {
        dbg_ERROR(DBG_ICMPv4, "copy failed");
        pktbuf_free(new_buf);
        return err;
    }
    
    err = icmpv4_out(dest_ip, src, new_buf);
    if (err < 0)
    {
        dbg_ERROR(DBG_ICMPv4, "send icmp unreach");
        pktbuf_free(new_buf);
        return err;
    }
    return NET_ERR_OK;
}