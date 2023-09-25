#include "tcp_in.h"
#include "tcp_out.h" 
#include "tcp_state.h"

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
    static const tcp_state_proc tcp_state_proc[] = {
        [TCP_STATE_CLOSED] = tcp_closed_in,
        [TCP_STATE_SYN_SENT] = tcp_syn_sent_in,
        [TCP_STATE_ESTABLISHED] = tcp_established_in,
        [TCP_STATE_FIN_WAIT_1] = tcp_fin_wait_1_in,
        [TCP_STATE_FIN_WAIT_2] = tcp_fin_wait_2_in,
        [TCP_STATE_CLOSING] = tcp_closing_in,
        [TCP_STATE_TIME_WAIT] = tcp_time_wait_in,
        [TCP_STATE_CLOSE_WAIT] = tcp_close_wait_in,
        [TCP_STATE_LAST_ACK] = tcp_last_ack_in,      
    };
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

    tcp_display_pkt("tcp in", tcp_hdr, buf);

    tcp_seg_t seg;
    tcp_seg_init(&seg, buf, dest, src);
    //tcp_send_reset(&seg);

    tcp_t* tcp = tcp_find(dest, tcp_hdr->dport, src, tcp_hdr->sport);
    if (!tcp)
    {
        dbg_info(DBG_TCP, "tcp connection not found");
        tcp_send_reset(&seg);
        pktbuf_free(buf);
    }


    tcp_state_proc[tcp->state](tcp, &seg);

    tcp_show_list();
    return NET_ERR_OK;
}

/**
 * @brief 目前作用是检查一下是否该发送fin包
 * 如果要发送fin包，需要把snd的next指针往后移一位，然后唤醒所有等待的接口
 * 如果不需要发送，那么说明来的是正常的数据，只唤醒等待读的接口就ok
 * @param tcp 
 * @param seg 
 * @return ** net_err_t 
 */
net_err_t tcp_data_in (tcp_t* tcp, tcp_seg_t* seg)
{
    int wakeup = 0;
    tcp_hdr_t* tcp_hdr = seg->hdr;
    if (tcp_hdr->f_fin)
    {
        tcp->rcv.nxt++;
        wakeup++;
    }

    if (wakeup > 0)
    {
        if (tcp_hdr->f_fin)
            sock_wakeup((sock_t*)tcp, SOCK_WAIT_ALL, NET_ERR_CLOSE);
        else
            sock_wakeup((sock_t*)tcp, SOCK_WAIT_READ, NET_ERR_OK);
        
        tcp_send_ack(tcp, seg);
    }
    return NET_ERR_OK;
}

