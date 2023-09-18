#ifndef TCP_OUT_C
#define TCP_OUT_C

#include "tcp.h"

net_err_t tcp_send_reset(tcp_seg_t* seg);
net_err_t tcp_send_syn(tcp_t* tcp);

#endif