#include "tcp_out.h"
#include "ipv4.h"
#include "tcp_buf.h"

int tcp_write_sndbuf (tcp_t* tcp, const uint8_t* buf, int len)
{
    int free_cnt = tcp_buf_free_cnt(&tcp->snd.buf);
    if (free_cnt < len)
        return 0;
    
    int wr_len = (len > free_cnt) ? free_cnt : len;
    tcp_buf_write_send(&tcp->snd.buf, buf, wr_len);
    return wr_len;
}

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

/**
 * @brief 获得tcp发送时的缓存相对偏移和发送长度
 * 这一段比较绕，建议画个图看看
 * @param tcp   待发送的tcp结构
 * @param doff  buf内待发送的位置
 * @param dlen  待发送的长度
 * @return ** void 
 */
static void get_send_info (tcp_t* tcp, int* doff, int* dlen)
{
    // 非重发时，因为每确认一段，tcp就会从缓存中移除一段
    // 所以目前tcp发送缓存中的第一个字节是tcp未确认的第一个字节
    // 那么拿将要发送的字节减去未确认的第一个字节，就能得到将要发送的字节相对于发送缓存的相对偏移
    *doff = tcp->snd.nxt - tcp->snd.una;
    
    // 发送的总长度是:缓存内有多少个数据-发送的偏移，目前没有管窗口大小问题
    *dlen = tcp_buf_cnt(&tcp->snd.buf) - *doff;
    if (*dlen == 0)
        return;
}

static int copy_send_data (tcp_t* tcp, pktbuf_t* buf, int doff, int dlen)
{
    if (dlen == 0)
        return 0;
    
    // 此时的pktbuf包头是填充好的，扩大一下包头用以填充数据
    net_err_t err = pktbuf_resize(buf, (int)(buf->total_size + dlen));
    if (err < 0)
    {
        dbg_error(DBG_TCP, "pktbuf resize error");
        return -1;
    }

    // 定位到数据区域
    int hdr_size = tcp_hdr_size((tcp_hdr_t*)pktbuf_data(buf));
    pktbuf_reset_acc(buf);
    pktbuf_seek(buf, hdr_size);
    tcp_buf_read_send(&tcp->snd.buf, doff, buf, dlen);
    return dlen;
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
    hdr->f_syn = tcp->flags.syn_out;                    // 判断是否在发送握手包
    hdr->f_ack = tcp->flags.irs_valid;                  // 判断是否需要发送ack
    hdr->win = 1024;
    tcp_set_hdr_size(hdr, sizeof(tcp_hdr_t));

    if (tcp->flags.fin_out)
        hdr->f_fin = 1;

    int dlen, doff;
    get_send_info(tcp, &doff, &dlen);
    if (dlen < 0)
        return NET_ERR_OK;

    copy_send_data(tcp, buf, doff, dlen);

    tcp->snd.nxt += hdr->f_syn + hdr->f_fin + dlen;

    return send_out(hdr, buf, &tcp->base.remote_ip, &tcp->base.local_ip);

}

net_err_t tcp_send_syn(tcp_t* tcp)
{
    tcp->flags.syn_out = 1;
    return tcp_transmit(tcp);
    //return NET_ERR_OK;
}

/**
 * @brief 收到包时调用，处理握手和挥手时的标志位变化
 * 再根据收到数据包的seq和ack，来判断收到的包中是否携带了数据，还是说是单纯的握手和挥手包
 * @param tcp 
 * @param seg 
 * @return ** net_err_t 
 */
net_err_t tcp_ack_process (tcp_t* tcp, tcp_seg_t* seg)
{
    tcp_hdr_t* tcp_hdr = seg->hdr;
    // 当tcp处于sendin时的处理
    if (tcp->flags.syn_out)
    {
        tcp->snd.una++;                     // 走到这里，说明发的第一个握手包已经被确认，让已接收的窗口+1
        tcp->flags.syn_out = 0;             // 握手包发送完毕，置位，新的状态已经在上层函数调整过了
    }

    int acked_cnt = tcp_hdr->ack - tcp->snd.una;                    // 收到的包确认的长度是该包内的ack减去tcp结构内存储的已发送未确认的数值
    int unacked_cnt = tcp->snd.nxt - tcp->snd.una;                  // 此时tcp结构内已发送未确认的长度
    int curr_acked = (acked_cnt > unacked_cnt) ? unacked_cnt : acked_cnt;   // 选取上面两者中较小的部分
    // 如果收到的包是握手包，那么hdr的ack就会每次是+1，同时上面每次检测到tcp控制块处于syn_out状态时就会让una+1，所以acked_cnt就是0
    // 挥手包则要复杂一些，挥手包可能携带数据(也可能是我多考虑了)，所以获得的curr_acked肯定是要大于0的，会在下面进行处理
    // 而这里对挥手包处理的方式仅仅是将fin_out置0(不是很能理解有什么意义，但是后续的判断也都是根据这个0进行的)
    // 总之，如果curr_acked>0，那么可以认为收到的数据包携带数据，不是单纯的握手包
    if (curr_acked > 0)
    {
        // 把已确认的区域往后移一段
        tcp->snd.una += curr_acked;
        // 移除缓存中的已确认的数据
        curr_acked -= tcp_buf_remove(&tcp->snd.buf, curr_acked);
        // 如果是确认我方发送的
        // 只有一种情况curracked还有值，那就是当我方发一个fin报文，收到对方的回应包时
        // 如果curracked还有值，并且tcp控制块的fin_out位是1，才会进入，把fin_out置0，同上面所说，这不是很懂有什么意义
        if (curr_acked && (tcp->flags.fin_out))
            tcp->flags.fin_out = 0;
    }

    sock_wakeup(&tcp->base, SOCK_WAIT_WRITE, NET_ERR_OK);
    // 走到这里，不论如何都说明
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
    hdr->win = 1024;
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