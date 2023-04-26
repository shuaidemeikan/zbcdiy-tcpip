#include "mblock.h"
#include "debug.h"

/**
 * 初始化数据块，主要做以下几件事
 * 1、挂一个链表到数据块上
 * 2、根据传入的锁类型初始化锁和信号量
 * @param mblock 待初始化的数据块
 * @param mem 分割该块地址作为链表的节点
 * @param blk_size 链表一个节点的大小
 * @param cnt 链表内的节点数
 * @param locker_type 锁的类型
 * @return err类型的返回值
 */
net_err_t mblock_init(mblock_t* mblock, void* mem, int blk_size, int cnt, nlocker_type_t locker_type)
{
    // 先将mem读到buf里，方便后续操作
    uint8_t* buf = (uint8_t*)mem;
    nlist_init(&(mblock->free_list));
    /**
     * 这里是一个非常有意思的处理方式
     * 每次让buf+blk_size，把它转成nlist_node_t类型，然后直接调用链表节点的初始化函数
     * 这样可能会面临一个问题，就是我们把mem前面一段当成nlist_node_t来处理，直接用mem前面一段来存储链表的next和pre
     * 如果这一段mem是一个结构体，结构体内第一个节点就是nlist_node_t类型，那倒还好，但是假如结构体内的节点不是nlist_node_t呢
     * 那么该结构体最前面的几个字段就会被破坏，当我们对该结构体前面几个字段进行读写的时候，也会破坏next和pre节点
     * 但是，实际上却不会出现这种情况，因为当我们需要next和pre时，该节点一定是挂在链表上的，当我们需要对该结构体前面几个字段进行修改时
     * 该结构体一定从链表上被分配了出来，被分配出来之后，我们也不需要把它当成node来处理了
     * 当该结构体用完被回收的时候，回收的函数会对他next和pre进行配置，所以不会出现上面描述的情况
     */
    for (int i = 0; i < cnt; i++, buf += blk_size)
    {
        nlist_node_t* node = (nlist_node_t*)buf;
        nlist_node_init(node);
        nlist_insert_last(&(mblock->free_list), node);
    }

    // 初始化锁
    nlocker_init(&(mblock->locker), locker_type);

    // 根据锁的类型来决定是否初始化信号量
    if (locker_type != NLOCKER_NONE)
    {
        mblock->alloc_sem = sys_sem_create(cnt);
        // 如果信号量申请失败了
        if (mblock->alloc_sem == SYS_SEM_INVALID)
        {
            dbg_ERROR(DBG_MBLOCK, "create sem failed.");
            nlocker_destroy(&mblock->locker);
            return NET_ERR_SYS;
        }
    }
    return NET_ERR_OK;
}

/**
 * 分配一个空闲节点，如果没有空闲节点则根据当前传入的ms值来判断是否需要等待
 * ms为等待的时间，ms=0则说明一直等，ms<0表述忽视信号量，不等
 * @param block 从这个数据块中分配节点
 * @param ms 等待的时间
 * @return 分配到的节点，如果没有分配，则返回0
 */
void* mblock_alloc(mblock_t* block, int ms)
{
    // 先判断是否忽视信号量或者锁的类型是否是none
    if(ms < 0 || block->locker.type == NLOCKER_NONE)
    {
        nlocker_lock(&block->locker);
        // 判断数据块内还有多少空的节点，如果没有空的节点，由于忽视信号量，所以直接返回0
        int count = mblock_free_cnt(block);
        if (count == 0)
        {
            nlocker_unlock(&block->locker);
            return (void*)0;
        }
        // 还有空的节点，从链表头取一个节点
        else
        {
            nlist_node_t* node = nlist_remove_first(&(block->free_list));
            nlocker_unlock(&block->locker);
            return node;
        }   
    }
    // ms为正数并且锁的类型为正常，需要等待信号量
    else
    {
        // 等的时间结束了还没等到，直接返回0
        if (sys_sem_wait(block->alloc_sem, ms) < 0)
            return 0;
        else
        {
            // 否则和之前一样从链表头分配一个节点
            nlocker_lock(&(block->locker));
            nlist_node_t* node = nlist_remove_first(&(block->free_list));
            nlocker_unlock(&block->locker);
            return node;
        }
    }
}

/**
 * 获得数据块中有多少空闲节点
 * @param mblock 待统计的数据块
 * @return 空闲节点数
 */
int mblock_free_cnt(mblock_t* block)
{
    nlocker_lock(&block->locker);
    int count = nlist_count(&(block->free_list));
    nlocker_unlock(&block->locker);
    return count;
}

/**
 * 插入新的节点
 * @param mblock 待被插入的数据块
 * @param block  带插入的节点
 */
void mblock_free(mblock_t* mblock, void* block)
{
    // 先插入传入的节点
    nlocker_lock(&mblock->locker);
    nlist_insert_last(&mblock->free_list, block);
    nlocker_unlock(&mblock->locker);

    // 判断该块具有的锁的类型
    if (mblock->locker.type != NLOCKER_NONE)
        sys_sem_notify(mblock->alloc_sem);
}


/**
 * 销毁整个数据块
 * @param mblock 待销毁的数据块
 */
void mblock_destroy(mblock_t* mblock)
{
    // 我们需要释放的只有锁和信号量，所以需要先判断这个块是否具有这两个东西
    if (mblock->locker.type != NLOCKER_NONE)
    {
        sys_sem_free(mblock->alloc_sem);
        nlocker_destroy(&mblock->locker);
    }
}