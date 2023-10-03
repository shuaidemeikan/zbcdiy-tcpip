#ifndef TCP_BUF_H
#define TCP_BUF_H

#include <stdint.h>
#include "net_err.h"
#include "pktbuf.h"

typedef struct _tcp_sbuf_t
{
    int count;
    int in, out;
    int size;
    uint8_t* data;
}tcp_buf_t;

void tcp_buf_init(tcp_buf_t* buf, uint8_t* data, int size);

static inline int tcp_buf_size (tcp_buf_t* buf)
{
    return buf->size;
}

static inline int tcp_buf_free_cnt (tcp_buf_t* buf)
{
    return buf->size - buf->count;
}

static inline int tcp_buf_cnt (tcp_buf_t* buf)
{
    return buf->count;
}

void tcp_buf_write_send (tcp_buf_t* buf, const uint8_t* buffer, int len);
void tcp_buf_read_send (tcp_buf_t* buf, int offset, pktbuf_t* dest, int count);
int tcp_buf_write_rcv(tcp_buf_t * dest, int offset, pktbuf_t * src, int total);
int tcp_buf_remove(tcp_buf_t * buf, int cnt);
#endif