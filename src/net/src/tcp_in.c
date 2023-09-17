#include "tcp_in.h"
#include "tcp_out.h" 

void tcp_seg_init (tcp_seg_t* seg, pktbuf_t* buf, ipaddr_t* src, ipaddr_t* dest)
{
    seg->buf = buf;
    seg->hdr = (tcp_hdr_t*)pktbuf_data(buf);

    ipaddr_copy(&seg->local_ip, src);
    ipaddr_copy(&seg->remote_ip, dest);
    seg->data_len = buf->total_size - tcp_hdr_size(seg->hdr);
    seg->seq = seg->hdr->seq;
    seg->seq_len = seg->data_len + seg->hdr->f_syn + seg->hdr->f_fin; 
}

net_err_t tcp_in (pktbuf_t* buf, ipaddr_t* src, ipaddr_t* dest)
{
    tcp_hdr_t* tcp_hdr = (tcp_hdr_t*)pktbuf_data(buf);
    if (tcp_hdr->checksum)
    {
        pktbuf_reset_acc(buf);
        if (checksum_peso(src->a_addr, dest->a_addr, NET_PROTOCOL_TCP, buf))
        {
            dbg_warning(DBG_TCP, "tcp check sum failed");
            return NET_ERR_BROKEN;
        }
    }

    if ((buf->total_size < sizeof(tcp_hdr_t)) || (buf->total_size < tcp_hdr_size(tcp_hdr)))
    {
        dbg_warning(DBG_TCP, "tcp header too small");
        return NET_ERR_SIZE;
    }

    if (!tcp_hdr->sport || !tcp_hdr->dport)
    {
        dbg_warning(DBG_TCP, "tcp header has no port");
        return NET_ERR_BROKEN;
    }

    if (tcp_hdr->flags == 0)
    {
        dbg_warning(DBG_TCP, "tcp header has no flags");
        return NET_ERR_BROKEN; 
    }

    tcp_hdr->sport = x_ntohs(tcp_hdr->sport);
    tcp_hdr->dport = x_ntohs(tcp_hdr->dport);
    tcp_hdr->seq = x_ntohl(tcp_hdr->seq);
    tcp_hdr->ack = x_ntohl(tcp_hdr->ack);
    tcp_hdr->win = x_ntohs(tcp_hdr->win);
    tcp_hdr->urgptr = x_ntohs(tcp_hdr->urgptr);

    tcp_seg_t seg;
    tcp_seg_init(&seg, buf, dest, src);
    tcp_send_reset(&seg);

    return NET_ERR_OK;
}