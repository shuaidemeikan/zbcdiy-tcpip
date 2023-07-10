#ifndef PKTBUF_H
#define PKTBUF_H

#include <stdint.h>
#include "nlist.h"
#include "net_cfg.h"
#include "net_err.h"

typedef struct _pktblk_t
{
    nlist_node_t node;
    int size;
    uint8_t* data;
    uint8_t payload[PKTBUF_BLK_SIZE];
}pktblk_t;

typedef struct _pktbuf_t
{
    int total_size;
    nlist_t blk_list;
    nlist_node_t node;

    int res;                    // 引用计数，用来判断当前pktbuf是否可以释放
    // 后三个参数在一起构成了“块指针”，表明当前buf正在操作哪个块
    int pos;                    // 从当前块起始点到当前块指针指向的地方的总大小
    pktblk_t* curr_blk;         // 当前在操作哪一个块
    uint8_t* blk_offset;        // 当前块操作的偏移
    // 注意，blk_offset表面上是当前块操作的偏移，但是实际上存储的是一个地址，这个地址指向的恰好是当前块操作的偏移
    // 也就是说如果我们要操作当前块的数据，直接操作blk_offset就可以了，不需要管curr_blk
}pktbuf_t;

net_err_t pktbuf_init(void);
pktbuf_t* pktbuf_alloc(int size);
void pktbuf_free(pktbuf_t* buf);

static inline pktblk_t * pktblk_blk_next (pktblk_t * blk)
 {
    nlist_node_t * next = nlist_node_next(&blk->node);
    return nlist_entry(next, pktblk_t, node);
}

static inline pktblk_t * pktblk_blk_pre (pktblk_t * blk) 
{
    nlist_node_t * pre = nlist_node_pre(&blk->node);
    return nlist_entry(pre, pktblk_t, node);
}

static inline pktblk_t * pktbuf_first_blk (pktbuf_t * buf) 
{
    nlist_node_t * first = nlist_first(&buf->blk_list);
    return nlist_entry(first, pktblk_t, node);
}

static inline pktblk_t * pktbuf_last_blk (pktbuf_t * buf) 
{
    nlist_node_t * last = nlist_last(&buf->blk_list);
    return nlist_entry(last, pktblk_t, node);
}

static inline int pktbuf_total(pktbuf_t* buf)
{
    return buf->total_size;
}

static inline uint8_t* pktbuf_data(pktbuf_t* buf)
{
    pktblk_t* first = pktbuf_first_blk(buf);
    return first ? first->data : (uint8_t*)0;
}

static inline void pktbuf_inc_ref(pktbuf_t* buf)
{
    buf->res = buf->res + 1;
}

net_err_t pktbuf_add_header(pktbuf_t* buf, int size, int cont);
net_err_t pktbuf_remove_header(pktbuf_t* buf, int size);
net_err_t pktbuf_resize(pktbuf_t* buf, int to_size);
net_err_t pktbuf_join (pktbuf_t * dest, pktbuf_t * src);
net_err_t pktbuf_set_cont(pktbuf_t * buf, int size);
void pktbuf_reset_acc(pktbuf_t * buf);
net_err_t pktbuf_write (pktbuf_t * buf, uint8_t * src, int size);
net_err_t pktbuf_read (pktbuf_t * buf, uint8_t * dest, int size);
net_err_t pktbuf_seek (pktbuf_t * buf, int offset);
net_err_t pktbuf_copy (pktbuf_t * dest, pktbuf_t * src, int size);
net_err_t pktbuf_fill (pktbuf_t * buf, uint8_t v, int size);

#endif
