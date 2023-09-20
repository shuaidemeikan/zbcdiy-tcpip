#include "tcp_state.h"
#include "tcp_out.h"
#include "tcp_in.h"

const char * tcp_state_name (tcp_state_t state)
{
    static const char * state_name[] = {
        [TCP_STATE_FREE] = "FREE",
        [TCP_STATE_CLOSED] = "CLOSED",
        [TCP_STATE_LISTEN] = "LISTEN",
        [TCP_STATE_SYN_SENT] = "SYN_SENT",
        [TCP_STATE_SYN_RECVD] = "SYN_RCVD",
        [TCP_STATE_ESTABLISHED] = "ESTABLISHED",
        [TCP_STATE_FIN_WAIT_1] = "FIN_WAIT_1",
        [TCP_STATE_FIN_WAIT_2] = "FIN_WAIT_2",
        [TCP_STATE_CLOSING] = "CLOSING",
        [TCP_STATE_TIME_WAIT] = "TIME_WAIT",
        [TCP_STATE_CLOSE_WAIT] = "CLOSE_WAIT",
        [TCP_STATE_LAST_ACK] = "LAST_ACK",

        [TCP_STATE_MAX] = "UNKNOWN",
    };

    if (state >= TCP_STATE_MAX)
        state = TCP_STATE_MAX;
    
    return state_name[state];
}

void tcp_set_state (tcp_t * tcp, tcp_state_t state)
{
    tcp->state = state;
}

void tcp_time_wait (tcp_t * tcp) {
    tcp_set_state(tcp, TCP_STATE_TIME_WAIT);
}

net_err_t tcp_closed_in(tcp_t *tcp, tcp_seg_t *seg)
{
    return NET_ERR_OK;
}

net_err_t tcp_syn_sent_in(tcp_t *tcp, tcp_seg_t *seg)
{
    tcp_hdr_t* tcp_hdr = seg->hdr;

    // 检查ack值的合法性 
    // 此时应当收到一个fack=1的包，但是也有可能收到一个没有fack的包，因为可能存在同时打开的情况
    if (tcp_hdr->f_ack)
    {
        // ack如果比起始小，或比下一个发送的字节大，那肯定是错误的
        if ((tcp_hdr->ack - tcp->snd.iss <= 0) || (tcp_hdr->ack - tcp->snd.nxt > 0))
        {
            dbg_warning(DBG_TCP, "tcp sendin state recv acck err");
            return tcp_send_reset(seg);
        }
    }

    // 检查rst位，看看包是不是rst包
    if (tcp_hdr->f_rst)
    {
        // 因为目前是在sys_send状态，必须确保收到的包存在ack，如果不存在，直接返回不处理这个包
        if (!tcp_hdr->f_ack)
            return NET_ERR_OK;
        
        dbg_warning(DBG_TCP, "tcp state send recv rst packet");
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 检查syn位，看看包是不是syn包，此时已经检查过ack和rst了
    // 所以报文只有两种，对方发来的syn打开报文和对方发来的syn回应报文，如果是前者，没有ack，如果是后者，有ack
    if (tcp_hdr->f_syn)
    {
        // 收到这个包意味着我方认为连接建立或待建立连接
        tcp->rcv.iss = tcp_hdr->seq;                // 我方接收起始序列应该是对方的seq     
        tcp->rcv.nxt = tcp_hdr->seq + 1;            // 我方待接收应该是seq+1，因为对方已经发送了一个syn
        tcp->flags.irs_valid = 1;                   // 将tcp状态设为收到对方的起始序号
        // ack位存在，则说明是对方发来的响应包
        if (tcp_hdr->f_ack)
        {
            tcp_ack_process(tcp, seg);              // 处理ack
        }
        tcp_send_ack(tcp, seg);
        tcp_set_state(tcp, TCP_STATE_ESTABLISHED);
        sock_wakeup(&tcp->base, SOCK_WAIT_CONN, NET_ERR_OK);
    }

    // 其他类型的包，直接返回不处理
    return NET_ERR_OK;
}

net_err_t tcp_established_in(tcp_t *tcp, tcp_seg_t *seg)
{
    tcp_hdr_t* tcp_hdr = seg->hdr;

    // 检查rst位，判断收到的是不是rst报文
    if (tcp_hdr->f_rst)
    {
        dbg_warning(DBG_TCP, "tcp state established recv rst packet");
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 检查syn位，如果发现有同样的四元组发syn报文，也直接断开
    // 实际协议栈不是这么做的，如果收到syn报文，会返回ack和seq的信息，但是这里就不实现这么复杂了
    if (tcp_hdr->f_syn)
    {
        dbg_warning(DBG_TCP, "tcp state established recv syn packet");
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 处理一下ack
    if (tcp_ack_process(tcp, seg))
    {
        dbg_warning(DBG_TCP, "ack process failed");
        return NET_ERR_UNREACH;
    }

    tcp_data_in(tcp, seg);
    if (tcp_hdr->f_fin)
        tcp_set_state(tcp, TCP_STATE_CLOSE_WAIT);

    return NET_ERR_OK;
}

net_err_t tcp_close_wait_in (tcp_t * tcp, tcp_seg_t * seg)
{
    return NET_ERR_OK;
}

net_err_t tcp_last_ack_in (tcp_t * tcp, tcp_seg_t * seg)
{
    tcp_hdr_t* tcp_hdr = seg->hdr;

    // 检查rst位，判断收到的是不是rst报文
    if (tcp_hdr->f_rst)
    {
        dbg_warning(DBG_TCP, "tcp state established recv rst packet");
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 检查syn位，如果发现有同样的四元组发syn报文，也直接断开
    // 实际协议栈不是这么做的，如果收到syn报文，会返回ack和seq的信息，但是这里就不实现这么复杂了
    if (tcp_hdr->f_syn)
    {
        dbg_warning(DBG_TCP, "tcp state established recv syn packet");
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_ack_process(tcp, seg))
    {
        dbg_warning(DBG_TCP, "ack process failed");
        return NET_ERR_UNREACH;
    }

    return tcp_abort(tcp, NET_ERR_CLOSE);
}

net_err_t tcp_fin_wait_1_in(tcp_t * tcp, tcp_seg_t * seg)
{
     tcp_hdr_t* tcp_hdr = seg->hdr;

    // 检查rst位，判断收到的是不是rst报文
    if (tcp_hdr->f_rst)
    {
        dbg_warning(DBG_TCP, "tcp state established recv rst packet");
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 检查syn位，如果发现有同样的四元组发syn报文，也直接断开
    // 实际协议栈不是这么做的，如果收到syn报文，会返回ack和seq的信息，但是这里就不实现这么复杂了
    if (tcp_hdr->f_syn)
    {
        dbg_warning(DBG_TCP, "tcp state established recv syn packet");
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 处理一下ack
    if (tcp_ack_process(tcp, seg))
    {
        dbg_warning(DBG_TCP, "ack process failed");
        return NET_ERR_UNREACH;
    }

    tcp_data_in(tcp, seg);
    
    if (tcp_hdr->f_fin)
        // 如果fin=1，则代表同时收到了对方发的第一次挥手，直接进入timewait状态
        tcp_time_wait(tcp);
    else
        // fin=0，又通过了种种检查，则说明对方回应了我方第一次挥手的包，进入wait2状态并等待下一个包
        tcp_set_state(tcp, TCP_STATE_FIN_WAIT_2);

    return NET_ERR_OK;
}

net_err_t tcp_fin_wait_2_in(tcp_t * tcp, tcp_seg_t * seg)
{
    tcp_hdr_t* tcp_hdr = seg->hdr;

    // 检查rst位，判断收到的是不是rst报文
    if (tcp_hdr->f_rst)
    {
        dbg_warning(DBG_TCP, "tcp state established recv rst packet");
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 检查syn位，如果发现有同样的四元组发syn报文，也直接断开
    // 实际协议栈不是这么做的，如果收到syn报文，会返回ack和seq的信息，但是这里就不实现这么复杂了
    if (tcp_hdr->f_syn)
    {
        dbg_warning(DBG_TCP, "tcp state established recv syn packet");
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 处理一下ack
    if (tcp_ack_process(tcp, seg))
    {
        dbg_warning(DBG_TCP, "ack process failed");
        return NET_ERR_UNREACH;
    }

    tcp_data_in(tcp, seg);
    // 到目前这个阶段，tcp只会处理rst和第三次挥手的包，其他的包一律丢弃
    if (tcp_hdr->f_fin)
        // 针对第三次挥手的包，需要发一个ack的回应，但是已经在tcp_data_in里发过了，所以直接进入timewait环境即可
        tcp_time_wait(tcp);

    return NET_ERR_OK;
}

net_err_t tcp_closing_in (tcp_t * tcp, tcp_seg_t * seg)
{
    return NET_ERR_OK;
}

net_err_t tcp_time_wait_in (tcp_t * tcp, tcp_seg_t * seg)
{
    tcp_hdr_t* tcp_hdr = seg->hdr;

    // 检查rst位，判断收到的是不是rst报文
    if (tcp_hdr->f_rst)
    {
        dbg_warning(DBG_TCP, "tcp state established recv rst packet");
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 检查syn位，如果发现有同样的四元组发syn报文，也直接断开
    // 实际协议栈不是这么做的，如果收到syn报文，会返回ack和seq的信息，但是这里就不实现这么复杂了
    if (tcp_hdr->f_syn)
    {
        dbg_warning(DBG_TCP, "tcp state established recv syn packet");
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    // 处理一下ack
    if (tcp_ack_process(tcp, seg))
    {
        dbg_warning(DBG_TCP, "ack process failed");
        return NET_ERR_UNREACH;
    }

    // 如果再收到fin=1的报文，就说明之前我方发的第四次挥手的包对端没收到
    // 需要再发一次第四次挥手报文并重置timewait计时
    if (tcp_hdr->f_fin)
    {
        tcp_send_ack(tcp, seg);
        tcp_time_wait(tcp);
    }

    return NET_ERR_OK;
}

net_err_t tcp_listen_in(tcp_t *tcp, tcp_seg_t *seg)
{
    return NET_ERR_OK;
}

net_err_t tcp_syn_recvd_in(tcp_t *tcp, tcp_seg_t *seg)
{
    return NET_ERR_OK;
}