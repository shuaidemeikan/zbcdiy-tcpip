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
    out->f_rst = 1;
    tcp_set_hdr_size(out, sizeof(tcp_hdr_t));

    if (in->f_ack)
    {
        // 说明连接已经成功建立了
        out->seq = in->ack;
        out->ack = 0;
        out->f_ack = 0;
    }else
    {
        out->ack = in->seq + seg->seq_len;
    }

    if (in->f_ack)
    out->win = out->urgptr = 0;
    tcp_display_pkt("tcp out", out, buf);
    return send_out(out, buf, &seg->remote_ip, &seg->local_ip);
}

net_err_t tcp_transmit (tcp_t* tcp)
{
    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_hdr_t));
    if (!buf)
    {
        dbg_error(DBG_TCP, "no pktbuf");
        return NET_ERR_OK;
    }

    tcp_hdr_t* hdr = (tcp_hdr_t*)pktbuf_data(buf);
    plat_memset(hdr, 0, sizeof(tcp_hdr_t));
    hdr->sport = tcp->base.local_port;
    hdr->dport = tcp->base.remote_port;
    hdr->seq = tcp->snd.nxt;
    hdr->ack = tcp->rcv.nxt;
    hdr->flags = 0;
    hdr->f_syn = tcp->flags.syn_out;
    hdr->f_ack = tcp->flags.irs_valid;
    hdr->win = 1024;
    tcp_set_hdr_size(hdr, sizeof(tcp_hdr_t));

    if (tcp->flags.fin_out)
        hdr->f_fin = 1;

    tcp->snd.nxt += hdr->f_syn + hdr->f_fin;

    return send_out(hdr, buf, &tcp->base.remote_ip, &tcp->base.local_ip);

}

net_err_t tcp_send_syn(tcp_t* tcp)
{
    tcp->flags.syn_out = 1;
    return tcp_transmit(tcp);
    //return NET_ERR_OK;
}

net_err_t tcp_ack_process (tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_hdr_t* tcp_hdr = seg->hdr;
    // 当tcp处于sendin时的处理
    if (tcp->flags.syn_out)
    {
        tcp->snd.una++;                     // 走到这里，说明发的第一个握手包已经被确认，让已接收的窗口+1
        tcp->flags.syn_out = 0;             // 握手包发送完毕，置位，新的状态已经在上层函数调整过了
    }
    return NET_ERR_OK;
}

net_err_t tcp_send_ack(tcp_t* tcp, tcp_seg_t* seg)
{
    // 如果是rst报文，不处理
    if (seg->hdr->f_rst)
        return NET_ERR_OK;
    
    pktbuf_t* buf = pktbuf_alloc(sizeof(tcp_hdr_t));
    if (!buf)
    {
        dbg_error(DBG_TCP, "no pktbuf");
        return NET_ERR_OK;
    }

    tcp_hdr_t* hdr = (tcp_hdr_t*)pktbuf_data(buf);
    plat_memset(hdr, 0, sizeof(tcp_hdr_t));
    hdr->sport = tcp->base.local_port;
    hdr->dport = tcp->base.remote_port;
    hdr->seq = tcp->snd.nxt;
    hdr->ack = tcp->rcv.nxt;
    hdr->flags = 0;
    hdr->f_ack = 1;
    hdr->win = 0;
    hdr->urgptr = 0;
    tcp_set_hdr_size(hdr, sizeof(tcp_hdr_t));

    return send_out(hdr, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

net_err_t tcp_send_fin (tcp_t* tcp)
{
    tcp->flags.fin_out = 1;
    tcp_transmit(tcp);
    return NET_ERR_OK;
}