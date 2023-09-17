#include "tcp_out.h"
#include "ipv4.h"

static net_err_t send_out(tcp_hdr_t* out, pktbuf_t* buf, ipaddr_t* remote_ip, ipaddr_t* local_ip)
{
    out->sport = x_htons(out->sport);
    out->dport = x_htons(out->dport);
    out->seq = x_htonl(out->seq);
    out->ack = x_htonl(out->ack);
    out->win = x_htons(out->win);
    out->urgptr = x_htons(out->urgptr);
    out->checksum = 0;
    out->checksum = checksum_peso(remote_ip->a_addr, local_ip->a_addr, NET_PROTOCOL_TCP, buf);

    net_err_t err = ipv4_out(NET_PROTOCOL_TCP, remote_ip, local_ip, buf);
    if (err < 0)
    {
        dbg_warning(DBG_TCP, "ipv4_out failed");
        pktbuf_free(buf);
    }
    return NET_ERR_OK;
}

net_err_t tcp_send_reset(tcp_seg_t* seg)
{
    tcp_hdr_t* in = seg->hdr;

    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_hdr_t));
    if (!buf)
    {
        dbg_warning(DBG_TCP, "no pktbuf");
        return NET_ERR_NONE;
    }

    tcp_hdr_t* out = (tcp_hdr_t*)pktbuf_data(buf);
    out->sport = in->dport;
    out->dport = in->sport;
    out->flags = 0;
    out->ack = 1;
    tcp_set_hdr_size(out, sizeof(tcp_hdr_t));

    out->win = out->urgptr = 0;
    return send_out(out, buf, &seg->remote_ip, &seg->local_ip);
}