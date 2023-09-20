#ifndef TCP_OUT_C
#define TCP_OUT_C

#include "tcp.h"

net_err_t tcp_send_reset(tcp_seg_t* seg);
net_err_t tcp_send_syn(tcp_t* tcp);
net_err_t tcp_send_ack(tcp_t* tcp, tcp_seg_t* seg);
net_err_t tcp_ack_process (tcp_t* tcp, tcp_seg_t* seg);

#endif