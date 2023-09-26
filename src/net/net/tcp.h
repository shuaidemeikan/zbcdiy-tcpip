#ifndef TCP_H
#define TCP_H

#include "sock.h"
#include "debug.h"
#include "pktbuf.h"
#include "tools.h"
#include "protocol.h"
#include "socket.h"
#include "tcp_buf.h"

#pragma pack(1)
typedef struct _tcp_hdr_t
{
    uint16_t sport;
    uint16_t dport;

    uint32_t seq;
    uint32_t ack;

    union 
    {
        uint16_t flags;
#if NET_ENDIAN_LITTLE
    struct 
    {
        uint16_t resv : 4;
        uint16_t shdr : 4;
        uint16_t f_fin : 1;
        uint16_t f_syn : 1;
        uint16_t f_rst : 1;
        uint16_t f_psh : 1;
        uint16_t f_ack : 1;
        uint16_t f_urg : 1;
        uint16_t f_ece : 1;
        uint16_t f_cwr : 1;
    };
#else
    struct
    {
        uint16_t shdr : 4;
        uint16_t resv : 4;
        uint16_t f_cwr : 1;
        uint16_t f_ece : 1;
        uint16_t f_urg : 1;
        uint16_t f_ack : 1;
        uint16_t f_psh : 1;
        uint16_t f_rst : 1;
        uint16_t f_syn : 1;
        uint16_t f_fin : 1;
    };
#endif
    };
    uint16_t win;
    uint16_t checksum;
    uint16_t urgptr;
    
}tcp_hdr_t;

typedef struct _tcp_pkt_t
{
    tcp_hdr_t hdr;
    uint8_t data[1];
}tcp_pkt_t;


#pragma pack()

typedef struct _tcp_seg_t
{
    ipaddr_t local_ip;
    ipaddr_t remote_ip;
    tcp_hdr_t* hdr;
    pktbuf_t* buf;
    uint32_t data_len;
    uint32_t seq;
    uint32_t seq_len;
}tcp_seg_t;

typedef enum _tcp_state_t {
    TCP_STATE_FREE = 0,             // 空闲状态，非标准状态的一部分
    TCP_STATE_CLOSED,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECVD,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,

    TCP_STATE_MAX,
}tcp_state_t;

typedef struct _tcp_t
{
    sock_t base;

    tcp_state_t state;
    struct
    {
        uint32_t syn_out : 1;        // 输出syn标志位
        // 这个位只有在我方主动给远端发送一个第一次挥手包的时候才会被置1，接着在收到远端确认的第二次挥手包时就被置0
        // 当收到挥手包时，存在以下几种情况:
        //1.在establesd时收到远端发来的第一次挥手包，实际的处理仅仅只是唤醒所有等待的线程，不会操作这个位
        //2.在fin_wait_1时收到远端发来的针对我方发的第一次挥手的确认包，在进入finwait1状态时，这个位会被置1，接着在这时被置0
        //3.其余所有情况，都不会设计操作这个位
        uint32_t fin_out : 1;        // 需要发送FIN，在收到第二次挥手的包时，就会被置0
        uint32_t irs_valid : 1;      // 初始序列号irs不可用
    }flags;

    struct
    {
        sock_wait_t wait;
    }conn;

    struct
    {
        tcp_buf_t buf;
        uint8_t data[TCP_SBUF_SIZE];
        uint32_t una;                   // 已发送但未确认区域的起始序号
        uint32_t nxt;                   // 未发送的起始序号
        uint32_t iss;                   // 起始发送序号
        sock_wait_t wait;
    }snd;

    struct 
    {
        uint32_t nxt;                   // 下一个期望接收的序号
        uint32_t iss;                   // 起始接收序号
        sock_wait_t wait;
    }rcv;
    
}tcp_t;

static inline uint16_t tcp_hdr_size (tcp_hdr_t* tcp)
{
    return tcp->shdr * 4;
}

static inline void tcp_set_hdr_size (tcp_hdr_t* tcp, int size)
{
    tcp->shdr = size / 4;
}

net_err_t tcp_init(void);
sock_t* tcp_create (int family, int protocol);
tcp_t* tcp_find(ipaddr_t* dest, uint16_t dport, ipaddr_t* src, uint16_t sport);
net_err_t tcp_abort (tcp_t* tcp, int err);
#if DBG_DISP_ENABLED(DBG_TCP)       // 注意头文件要包含dbg.h和net_cfg.h
void tcp_show_info (char * msg, tcp_t * tcp);
void tcp_display_pkt (char * msg, tcp_hdr_t * tcp_hdr, pktbuf_t * buf);
void tcp_show_list (void);
#else
#define tcp_show_info(msg, tcp)
#define tcp_display_pkt(msg, hdr, buf)
#define tcp_show_list()
#endif

#endif