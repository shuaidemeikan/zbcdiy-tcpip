#ifndef MBLOCK_H
#define MBLOCK_H

#include "nlist.h"
#include "nlocker.h"
#include "sys_plat.h"
#include "net_err.h"

typedef struct _mblock_t
{
    nlist_t free_list;
    void* start;
    nlocker_t locker;
    sys_sem_t alloc_sem;
}mblock_t;

net_err_t mblock_init(mblock_t* mblock, void* mem, int blk_size, int cnt, nlocker_type_t locker_type);
void* mblock_alloc(mblock_t* block, int ms);
int mblock_free_cnt(mblock_t* block);
void mblock_free(mblock_t* mblock, void* block);
void mblock_destroy(mblock_t* mblock);
#endif