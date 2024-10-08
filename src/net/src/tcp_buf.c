#include "tcp_buf.h"
#include "debug.h"

void tcp_buf_init(tcp_buf_t* buf, uint8_t* data, int size)
{
    buf->in = buf->out = 0;
    buf->count = 0;
    buf->size = size;
    buf->data = data;
}

void tcp_buf_write_send(tcp_buf_t * dest, const uint8_t * buffer, int len) {
    while (len > 0) {
        // 循环逐字节写入数据量
        dest->data[dest->in++] = *buffer++;
        if (dest->in >= dest->size) {
            dest->in = 0;
        }

        dest->count++;
        len--;
    }
}

// void tcp_buf_write_send (tcp_buf_t* buf, const uint8_t* buffer, int len)
// {
//     while (len > 0)
//     {
//         buf->data[buf->in++] = *buffer++;
//         if (buf->in >= buf->size)
//             buf->in = 0;
//         len--;
//         buf->count++;
//     }
// }

// void tcp_buf_read_send (tcp_buf_t* buf, int offset, pktbuf_t* dest, int count)
// {
//     uint8_t tmp[TCP_SBUF_SIZE];
//     if (pktbuf_read(dest, tmp, count) < 0)
//     {
//         dbg_error(DBG_TCP, "read buf failed");
//         return NET_ERR_MEM;
//     }

//     if (size = tcp_buf_free_cnt(buf) < count)
//     {
//         dbg_warning(DBG_TCP, "tcp buf is too small");
//         tcp_buf_free_cnt(buf);
//     }

//     int start = buf->out + offset;
//     if (start + count <= buf->size)
//         plat_memcpy(buf->data[start], tmp, count)
//     else
//     {
//         plat_memcpy(buf->data[start], tmp, buf->size - start);
//         tmp = tmp + (buf->size - start);
//         count -= (buf->size - start);
//         plat_memcpy(buf->data[0], tmp, count);
//     }
// }

void tcp_buf_read_send(tcp_buf_t * buf, int offset, pktbuf_t * dest, int count) {
    // 超过要求的数据量，进行调整
    int free_for_us = buf->count - offset;      // 跳过offset之前的数据
    if (count > free_for_us) {
        dbg_warning(DBG_TCP, "resize for send: %d -> %d", count, free_for_us);
        count = free_for_us;
    }

    // 复制过程中要考虑buf中的数据回绕的问题
    int start = buf->out + offset;     // 注意拷贝的偏移
    if (start >= buf->size) {
        start -= buf->size;
    }

    while (count > 0) {
        // 当前超过末端，则只拷贝到末端的区域
        int end = start + count;
        if (end >= buf->size) {
            end = buf->size;
        }
        int copy_size = (int)(end - start);

        // 写入数据
        net_err_t err = pktbuf_write(dest, buf->data + start, (int)copy_size);
        dbg_assert(err >= 0, "write buffer failed.");

        // 更新start，处理回绕的问题
        start += copy_size;
        if (start >= buf->size) {
            start -= buf->size;
        }
        count -= copy_size;

        // 不调整buf中的count和out，因为只当被确认时才需要
    }
}

int tcp_buf_write_rcv(tcp_buf_t * dest, int offset, pktbuf_t * src, int total) {
    // 计算缓冲区中的起始索引，注意回绕
    int start = dest->in + offset;
    if (start >= dest->size) {
        start = start - dest->size;
    }

    // 计算实际可写的数据量
    int free_size = tcp_buf_free_cnt(dest) - offset;            // 跳过的一部分相当于是已经被写入了
    total = (total > free_size) ? free_size : total;

    int size = total;
    while (size > 0) {
        // 从start到缓存末端的单元数量，可能其中有数据也可能没有
        int free_to_end = dest->size - start;

        // 大小超过到尾部的空闲数据量，只拷贝一部分
        int curr_copy = size > free_to_end ? free_to_end : size;
        pktbuf_read(src, dest->data + start, (int)curr_copy);

        // 增加写索引，注意回绕
        start += curr_copy;
        if (start >= dest->size) {
            start = start - dest->size;
        }

        // 增加已写入的数据量
        dest->count += curr_copy;
        size -= curr_copy;
    }

    dest->in = start;
    return total;
}

int tcp_buf_remove(tcp_buf_t* buf, int cnt)
{
    if (cnt > buf->count)
        cnt = buf->count;
    
    buf->out += cnt;
    if (buf->out >= buf->size)
        buf->out -= buf->size;
    
    buf->count -= cnt;
    return cnt;
}

int tcp_buf_read_rcv(tcp_buf_t* buf, uint8_t* dest, int count)
{
    int total= count > buf->count ? buf->count : count;

    int currr_size = 0;
    while (currr_size < total)
    {
        *dest++ = buf->data[buf->out++];
        if (buf->out >= buf->size)
            buf->out = 0;
        
        buf->count--;
        currr_size++;
    }
    return total;
}
