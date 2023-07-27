#include "pktbuf.h"
#include "nlocker.h"
#include "debug.h"
#include "mblock.h"
#include "sys.h"
#include "tools.h"

// 这里定义了整个网络协议栈用来收发数据的数据块
// block_buffer是具体用来存储payload的数据块，由block_list串起来
// pktbuf_buffer是用来管理存储payload的数据块，由pktbuf_list串起来
static nlocker_t locker;
static pktblk_t block_buffer[PKTBUF_BLK_CNT];
static mblock_t block_list;
static pktbuf_t pktbuf_buffer[PKTBUF_BUF_CNT];
static mblock_t pktbuf_list;

static void move_forward(pktbuf_t* buf, int size)
{
    // 先假定偏移往后移size个字节后还在当前包内
    buf->pos += size;
    buf->blk_offset += size;

    // 判断偏移往后移size个字节后还在不在当前包内
    pktblk_t* curr_blk = buf->curr_blk;
    if (buf->blk_offset >= curr_blk->data + curr_blk->size)
    {
        buf->curr_blk = pktblk_blk_next(curr_blk);
        if (buf->curr_blk)
        // 这里是很有意思的一点，明明上面判断的是>=,但是这里具体处理的方式却是按照=来处理的，我没弄明白
        // 可能是按照我们传参的习惯，传进来的参最多也就是=的情况，不会出现>=
            buf->blk_offset = buf->curr_blk->data;
        else
            buf->blk_offset = (uint8_t*)0;
    }
}

static inline int total_blk_remain(pktbuf_t* buf)
{
    return buf->total_size - buf->pos;
}

static inline int curr_blk_tail_free (pktblk_t * blk) 
{
    return (int)((blk->payload + PKTBUF_BLK_SIZE) - (blk->data + blk->size));
}

static inline int curr_blk_remain(pktbuf_t* buf)
{
    pktblk_t* block = buf->curr_blk;
    if (!block)
        return 0;
    
    return (int)(block->data + block->size - buf->blk_offset);
}

/**
 * 单独回收一个pktblk_t节点
 * @param first 待回收的节点
 */
static void pktblock_free (pktblk_t* block)
{
    mblock_free(&block_list, block);
}

/**
 * 回收创建好的由pktblk_t组成的链表
 * @param first 待回收的链表的首节点
 */
static void pktblock_free_list (pktblk_t * first)
{
    while (first)
    {
        pktblk_t* pre = pktblk_blk_next(first);
        pktblock_free(first);
        first = pre;
    }
}

#if DBG_DISP_ENABLED(DBG_BUF) 
/**
 * 打印pktbuf内存储的list的易错数据，并且检验这些数据
 * @param buf 待打印和检验的pktbuf
 */
static void display_check_buf (pktbuf_t * buf) 
{
    if (!buf)
    {
        dbg_ERROR(DBG_BUF, "invalid buf, buf == 0");
        return;
    }
    dbg_info(DBG_BUF,"buf->size = %d", buf->total_size);
    // 遍历pktbuf里存的链表
    int curr_id = 0;
    // 统计一个pktbuf中实际的size，用于和pktbuf进行对比
    int total_size = 0;
    for (pktblk_t* curr = pktbuf_first_blk(buf); curr; curr = pktblk_blk_next(curr))
    {
        if ((curr->data) < (curr->payload) || (curr->data) >= ((curr->payload) + PKTBUF_BLK_SIZE))
        {
            dbg_ERROR(DBG_BUF, "bad block data");
            return;
        }
        /**
         * 为了方便，以下用node代替pktbuf
         * 根据插入方式不同，payload可以分为三个部分
         * 1、前半段空头，当使用头插法时，第一个node的多半data会指向payload中间，然后从data到payload末尾这一段是有数据的
         *    当使用尾插法时，就不存在前半段空头
         * 2、数据部分，不论是头插法还是尾插法，payload内一定是有数据的，不论是头插法还是尾插法，对于中间的节点，data指
         *    向payload的头部，数据会占满整个payload，但是当使用尾插法时，最后一个node的payload的纯粹的数据部分应该是
         *    占满payload的前半部分，当使用头插法时，第一个node的payload的纯粹的数据部分应该是占满payload的尾部部分
         * 3、后半段空值，当时用尾插法时，最后一个node的payload多半是占不满payload所有的空间的，所以一个payload的后半部分
         *    应该有一小段是空的
         * 综上所述，这三个部分还有一些特性，例如如果存在前半段空头，就不会存在后半段空值，反之也是一样
         */
        // 获取payload前半段空头长度
        plat_printf("packetid: %d, ", curr_id++);

        int head_free = (int)((curr->data) - (curr->payload));
        plat_printf("head_free: %d, ", head_free);

        // 获得payload的数据部分长度
        int payload_size = curr->size;
        plat_printf("payload_size: %d , ", payload_size);
        
        // 获得payload的后半段空值长度
        int end_free = (int)((curr->payload + PKTBUF_BLK_SIZE) - (curr->data + curr->size));
        plat_printf("end_free: %d\n", end_free);

        // 获得了三个东西，这三个东西加起来应该正好等于PKTBUF_BLK_SIZE，如果不等于，就打印报错信息
        int all_size = head_free + payload_size + end_free;
        if (all_size != PKTBUF_BLK_SIZE)
        {
            dbg_ERROR(DBG_BUF, "bad block size: %d != %d", all_size, PKTBUF_BLK_SIZE);
        }

        // 统计一下各个node加起来长度
        total_size += curr->size;
    }
    // 检测一下各个node的总长度加起来是不是等于buf里存的size
    if (total_size != buf->total_size)
        dbg_ERROR(DBG_BUF, "bad buf size: %d != %d", total_size, buf->total_size);
}
#else
#define display_check_buf(buf)
#endif

/**
 * 初始化整个用于控制数据包结构的数据块，该数据块数量由PKTBUF_BLK_CNT和PKTBUF_BUF_CNT定义
 * @return err类型的返回值
 */
net_err_t pktbuf_init(void)
{
    dbg_info(DBG_BUF, "init pktbuf...");

    // 初始化锁
    nlocker_init(&locker, NLOCKER_THREAD);
    // 初始化两个存储结构
    mblock_init(&block_list, block_buffer, sizeof(pktblk_t), PKTBUF_BLK_CNT, NLOCKER_THREAD);
    mblock_init(&pktbuf_list, pktbuf_buffer, sizeof(pktbuf_t), PKTBUF_BUF_CNT, NLOCKER_THREAD);
    //..........................................
    //pktbuf_buffer[1].total_size = 0;
    dbg_info(DBG_BUF, "init done.");
    return NET_ERR_OK;
}

/**
 * 上面我们已经在pktbuf_init里初始化了一个用来管理payload的mblock，这里我们直接从mblock里拿一个pktblk就可以了
 * 所以这个函数的功能就是返回一个pktblk
 * @return 一个pktblk
 */
static pktblk_t* pktblock_alloc(void)
{
    // 从mblock里获得一个pktblk，用于处理来自网卡的信息
    // 由于后续可能从中断里拿到来自网卡的信息，所以这里拒绝等待
    pktblk_t* block = mblock_alloc(&block_list, -1);
    // mblock_alloc如果没拿到会返回0，所以我们只需要对拿到的pktblk做处理，不需要对没拿到的情况做特殊的处理，直接返回就好
    if (block)
    {
        block->size = 0;
        block->data = (uint8_t*)0;
        nlist_node_init(&block->node);
    }
    return block;
}

/**
 * 以头插法或尾插法的方式获得一个完整的由pktblk组成的链表，用来处理从网卡接受到的数据
 * 这些数据会被分散到链表的各个节点来存储，一个节点存储多少数据由PKTBUF_BLK_SIZE宏决定
 * @param size 整个链表要储存的数据的大小
 * @param add_front 插入的方式，1代表头插法，0代表尾插法
 * @return 获得的链表的头节点
 */
static pktblk_t* pktblock_alloc_list(int size, int add_front)
{
    if (size == 0)
        dbg_ERROR(DBG_BUF, "try to get a pktblk if size 0");
    // 获得的链表的头节点，随后我们会直接返回这个
    pktblk_t* first_block = (pktblk_t*)0;
    // 上一次操作的节点
    pktblk_t* pre_block = (pktblk_t*)0;
    // 循环的把数据存储到链表的各个节点上
    while (size)
    {
        // 先申请到一个pktblk，这个申请到的pktblk只是经过简单的初始化，后面我们还需要对这个节点做处理
        pktblk_t* new_block = pktblock_alloc();
        // 如果这个节点没拿到就打印一个错误然后直接返回0
        if (!new_block)
        {
            dbg_ERROR(DBG_BUF, "no buffer for alloc(%d)", size);
            if (first_block)
                pktblock_free_list(first_block);
            return (pktblk_t*)0;
        }

        int curr_size = 0;
        // 判断是头插法还是尾插法，阅读的时候推荐从尾插法开始阅读
        if (add_front)
        {
            /**
             * 对于头插法，新的节点往链表的头部插入，所以链表的头部是在不断变化的
             * 这个时候表示头部节点的first_block就需要在每次有新的pktblk链到链表上的时候更新一下了
             * 这里的curr_size对比尾插法的作用也略有拓展
             * curr_size不仅仅表示pktblk size的值，还用来定位最后一个被插入的pktblk的payload从哪里开始，也就是pktblk中data的值
             */
            curr_size = size > PKTBUF_BLK_SIZE ? PKTBUF_BLK_SIZE : size;
            new_block->size = curr_size;
            new_block->data = new_block->payload + PKTBUF_BLK_SIZE - curr_size;
            if (first_block)
                nlist_node_set_next(&new_block->node, &first_block->node);
            
            // 更新first_block
            first_block = new_block;
        }else
        {
            /**
             * 对于尾插法，新的节点往链表的尾部插入，所以头部的节点是用于不会动的
             * 所以first_block我们只需要在第一次循环的时候给他赋值成第一次拿到的节点就行
             */
            if (!first_block)
                first_block = new_block;

            // 由于我们是循环的插入，当插入到最后一个节点的时候，最后一个节点的内存肯定用不完
            // 所以我们用curr_size来保存最后一个节点所用内存的大小，这样方便最后我们设置当前pktblk的size
            curr_size = size > PKTBUF_BLK_SIZE ? PKTBUF_BLK_SIZE : size;
            // 对pktblk内的一些属性进行更精细的设置
            new_block->size = curr_size;
            new_block->data = new_block->payload;
            // 如果这个时候有pre_block，也就是说这次获得的pktblk不是第一次获得，那么就把pktblk插入到pre_block后面
            if (pre_block)
                nlist_node_set_pre(&pre_block->node, &new_block->node);
        }

        size -= curr_size;
        pre_block = new_block;
    }
    return first_block;
}

/**
 * 把一个由pktblk组成的链表串到pktbuf的blk_list上
 * @param buf 被串的pktbuf
 * @param first_blk 由pktblk组成的链表的首节点
 * @param add_list 插入方式，1表示尾插法，0表示头插法
 */
static void pktbuf_insert_blk_list(pktbuf_t* buf, pktblk_t* first_blk, int add_list)
{
    // 判断是头插还是尾插
    if (add_list)
    {
        // 尾插法，每次让first_blk指向链表的下一个节点，first_blk为空则代表节点遍历完了
        while(first_blk)
        {
            // 先把当前节点的下一个节点读出来，方便指向，不然当我们用nlist_insert_last把当前节点修改之后，就读不到下一个节点了
            pktblk_t* next_blk = pktblk_blk_next(first_blk);
            nlist_insert_last(&buf->blk_list, &first_blk->node);
            buf->total_size += first_blk->size;
            // 把first_blk指向下一个节点
            first_blk = next_blk;
        }
    }else
    {
        /**
         * 头插法，这里需要先定义一个pre用来指向头节点，每次操作完first_blk就变成了pktbuf的头节点
         * 所以每次操作完都需要让pre=first_blk
         */
        pktblk_t* pre = (pktblk_t*)0;
        while (first_blk)
        {
            pktblk_t* next_blk = pktblk_blk_next(first_blk);
            if (pre)
                nlist_insert_after(&buf->blk_list, &pre->node, &first_blk->node);
            // 如果是第一次操作，pre理应是0，所以直接往头插入就好
            else
                nlist_insert_first(&buf->blk_list, &first_blk->node);
            
            pre = first_blk;
            first_blk = next_blk;
        }
    }
}

/**
 * 获得一个pktbuf_t用来接受来自网卡的数据，这个结构内的pktblk本质上是一个链表的头节点
 * 这些数据会被分散到内部的pktblk组成的链表的各个节点上存储，一个节点存储多少数据由PKTBUF_BLK_SIZE宏决定
 * @param size 整个链表要储存的数据的大小
 * @return 获得的pktbuf
 */
pktbuf_t* pktbuf_alloc(int size)
{
    // 分配到一个pktbuf_t，并且由于这个结构可能用来接收来自中断的数据，所以不等待
    pktbuf_t* buf = mblock_alloc(&pktbuf_list, -1);
    if (!buf)
    {
        dbg_ERROR(DBG_BUF, "no buffer.");
        return (pktbuf_t*)0;
    }
    // 对pktbuf_t进行一些简单的初始化
    buf->res = 1;
    buf->total_size = 0;
    nlist_init(&buf->blk_list);         // 这里初始化一个空链表，后续生成好的由pktblk组成的链表往这里扔就好
    nlist_node_init(&buf->node);

    if (size)
    {
        // 做一个链表出来，链表的长度是size决定的
        pktblk_t* block = pktblock_alloc_list(size, 1);
        if (!block)
        {
            mblock_free(&pktbuf_list, buf);
            return (pktbuf_t*)0;
        }
        // 把链表插入到pktbuf_t里面
        pktbuf_insert_blk_list(buf, block, 1);
        display_check_buf(buf);
    }

    pktbuf_reset_acc(buf);
    return buf;
}

/**
 * 回收创建好的pktbuf_t
 * @param buf 待回收的pktbuf_t
 */
void pktbuf_free(pktbuf_t* buf)
{
    nlocker_lock(&locker);
    if ((--(buf->res)) != 0)
    {
        pktblock_free_list(pktbuf_first_blk(buf));
        mblock_free(&pktbuf_list, buf);
    }
    nlocker_unlock(&locker);
}

/**
 * 给逻辑上的包添加一个包头
 * 这里存在一个问题，就是大多包头都是用结构体成员的方法来访问的，这种访问方式要求存储结构体的内存连续
 * 但是这里逻辑上的包本身内存是不连续，所以如果这个包头是上述类型的包头的话，我们必须保证包头在一个pktblk里面
 * @param buf 待被插入的包
 * @param size 包头的大小
 * @param cont 包头是否要求连续，1表示要求连续，0表示不要求连续
 * @return err类型的返回值
 */
net_err_t pktbuf_add_header(pktbuf_t* buf, int size, int cont)
{
    // 先检查传进来的buf是否是空包
    if (buf->blk_list.first == (nlist_node_t*)0)
    {
        dbg_ERROR(DBG_BUF, "buf is empty!");
        return NET_ERR_SIZE;
    }
    // 先拿到当前buf的第一个包，如果第一个包的payload前面的剩余空间刚好能放得下包头，那也就不用纠结后续的内容了
    pktblk_t* block = pktbuf_first_blk(buf);
    // 第一个包的payload前面的剩余空间
    int recv_size = (int)(block->data - block->payload);
    if (recv_size >= size)
    {
        // 对第一个包进行一些设置，这里比较迷惑的一点是并没有添加实际的内容进去
        buf->total_size += size;
        block->size += size;
        block->data -= size;
        display_check_buf(buf);
        return NET_ERR_OK;
    }

    // 如果第一个包加不下，那就得来纠结添加的这个包要不要求连续了
    if (cont)
    {
        // 要求连续，那么这里就有一个隐含条件，就是这个包的大小不能大于一个pktblk最大的大小
        if (size > PKTBUF_BLK_SIZE)
        {
            dbg_ERROR(DBG_BUF, "set cont, size too big: %d > %d", size, PKTBUF_BLK_SIZE);
            return NET_ERR_SIZE;
        }
        block = pktblock_alloc_list(size, 1);
        if (!block)
        {
            dbg_ERROR(DBG_BUF, "no buffer (size %d)", size);
            return NET_ERR_NONE;
        }
    } else
    {
        // 不要求连续，同时上面已经判断过添加的头部大小会超过第一个包头部剩余的空闲空间了，那么我们就得把第一个包的payload的前半部分利用起来
        block->data = block->payload;
        block->size += recv_size;
        buf->total_size += recv_size;
        size -= recv_size;

        block = pktblock_alloc_list(size, 1);
        if (!block)
        {
            dbg_ERROR(DBG_BUF, "no buffer (size %d)", size);
            return NET_ERR_NONE;
        }
    }

    // 把上面申请到的包添加到原来的buf上，用头插法
    pktbuf_insert_blk_list(buf, block, 0);
    display_check_buf(buf);
    return NET_ERR_OK;
}

/**
 * 给逻辑上的包移除一个包头
 * @param buf 待被移除的包
 * @param size 移除的包头的大小
 * @return err类型的返回值
 */
net_err_t pktbuf_remove_header(pktbuf_t* buf, int size)
{
    // 先检查一下需要移除的大小是否大于整个包
    if (size > buf->total_size)
    {
        dbg_ERROR(DBG_BUF, "need remove size is too big, need size: %d, total_size: %d", size, buf->total_size);
        return NET_ERR_SIZE;
    }

    pktblk_t* block = pktbuf_first_blk(buf);
    while (size)
    {
        // 后续当前节点会被释放，所以先把下一个节点取出来备用
        pktblk_t* next_blk = pktblk_blk_next(block);
        if (size < block->size)
        {
            block->size -= size;
            block->data += size;
            buf->total_size -= size;
            break;
        }

        int curr_size = block->size;
        // 先把当前节点从pktbuf存储的链表结构上释放
        nlist_remove_first(&buf->blk_list);
        // 再把当前节点回收进节点池
        pktblock_free(block);
        buf->total_size -= curr_size;
        size -= curr_size;
        block = next_blk;
    }
    display_check_buf(buf);
    return NET_ERR_OK;
}

/**
 * 调整一个逻辑包的大小，不论是扩大还是缩小，都是从尾部操作
 * @param buf 待被调整的包
 * @param size 调整后的大小
 * @return err类型的返回值
 */
net_err_t pktbuf_resize(pktbuf_t* buf, int to_size)
{
    // 先看看buf的大小和要调整至的大小是不是一样，一样的话直接返回就可以了
    if (buf->total_size == to_size)
        return NET_ERR_OK;
    
    // 再看看buf里面是不是空的，如果是的话直接申请一个大小为to_size的链表串到buf里就ok
    if (buf->total_size == 0)
    {
        pktblk_t* blk = pktblock_alloc_list(to_size, 0);
        if (!blk)
        {
            dbg_ERROR(DBG_BUF, "no block");
            return NET_ERR_MEM;
        }
        pktbuf_insert_blk_list(buf, blk, 1);
    // 如果上面两个都不走，那么就再看看是要扩大还是要缩小，这里进行的明显是缩扩大
    }else if(to_size > buf->total_size)
    {
        // 扩大是尾部扩大，所以需要对尾部的节点键处理
        pktblk_t* tail_blk = pktbuf_last_blk(buf);
        int inc_size = to_size - buf->total_size;               // 看看tosize比当前buf内的size大多少
        int remain_size = curr_blk_tail_free(tail_blk);         // 当前最后一个块剩余的空间
        // 如果最后一个块剩余的空间能放下，那么直接放在最后一个块剩余的空间就好了
        if (remain_size >= inc_size)
        {
            buf->total_size += inc_size;
            tail_blk->size += inc_size;
        // 否则就需要把最后一个块填满，然后申请一个新的链表来装剩下的，最后把新申请的链表尾部插入到buf内的链表上
        }else
        {
            // 申请一个新的链表，长度为最后一个块填满后，tosize还剩下的大小
            pktblk_t* new_blks = pktblock_alloc_list(inc_size - remain_size, 0);
            if (!new_blks)
            {
                dbg_ERROR(DBG_BUF, "no block");
                return NET_ERR_MEM;
            }
            // 在逻辑上填满最后一个块
            tail_blk->size += remain_size;
            buf->total_size += remain_size;
            // 把新的链表串到buf上
            pktbuf_insert_blk_list(buf, new_blks, 1);
        }
    }else if (to_size == 0)
    {
        pktblock_free_list(pktbuf_first_blk(buf));
        buf->total_size = 0;
        nlist_init(&buf->blk_list);
    }else
    {
        // 缩小，缩小也是从尾部缩小
        // 先看最后一个节点的总空间够不够缩小的
        pktblk_t* end_blk = pktbuf_last_blk(buf);
        int remain_size = (int)(buf->total_size - to_size);
        if (end_blk->size > remain_size)
        {
            end_blk->size -= remain_size;
            buf->total_size -= remain_size;
        }else
        {
            // 如果最后一个节点内的payload不够缩小的，那就说明从中间某个节点开始往后所有的节点都需要被舍弃
            // 那么就从头节点开始遍历，看看哪个节点前面所有的节点包括自己加起来大于to_size，那么该节点之后的所有节点都需要被舍弃
            pktblk_t* tail_blk = pktbuf_first_blk(buf);
            int total_size = 0;
            while (1)
            {
                total_size += tail_blk->size;
                if (total_size > to_size)
                    break;
                tail_blk = pktblk_blk_next(tail_blk);
            }
            // 程序跑到这，total_size就是上述我们要的节点，接下来我们还需要确定total_size之后的节点一共多大
            // 因为很可能total_size也有一部分需要被移除，我们需要确定total_size需要被移除多少，这里复用一下total_size
            total_size = 0;
            pktblk_t* curr_blk = pktblk_blk_next(tail_blk);
            while (curr_blk)
            {
                // 统计后面节点的总大小
                pktblk_t* next_blk = pktblk_blk_next(curr_blk);
                total_size += curr_blk->size;
                nlist_remove(&buf->blk_list, &curr_blk->node);
                pktblock_free(curr_blk);
                curr_blk = next_blk;
            }
            remain_size = buf->total_size - to_size - total_size;
            // 去掉后面节点，还有remain_size这么大的空间需要移除，在tail_blk移除
            tail_blk->size -= remain_size;
            buf->total_size = to_size;
        }
    }

    display_check_buf(buf);
    return NET_ERR_OK;
}

/**
 * 合并两个包，合并后dest被保留，src被释放
 * @param dest 合并后作为头部的包
 * @param src 合并后作为尾部的包，注意src会被释放
 * @return err类型的返回值
 */
net_err_t pktbuf_join (pktbuf_t * dest, pktbuf_t * src)
{
    // 先拿到src的头节点
    pktblk_t* src_first = pktbuf_first_blk(src);
    // 直接把头节点插入到dest，这样后续的节点也会跟着进来
    // 同时pktbuf_insert_blk_list这个函数还会自动处理dest的total_size，肥肠好用
    pktbuf_insert_blk_list(dest, src_first, 1);
    // 把链表从src上剥离出来，避免释放src的时候对上面的链表有影响，但是这是很危险的行为，一不小心就会把链表变成野指针，不能被正常回收
    (&src->blk_list)->first = (nlist_node_t*)0;
    (&src->blk_list)->last = (nlist_node_t*)0;
    pktbuf_free(src);
    display_check_buf(dest);
    return NET_ERR_OK;
}

/**
 * 合并一个包前size个字节，确保数据的连续性，在对数据包进行读的时候要先调用一下这个函数
 * @param buf 前size字节需要被合并的包
 * @param size 需要合并的字节数
 * @return err类型的返回值
 */
net_err_t pktbuf_set_cont(pktbuf_t * buf, int size)
{
    // size最大不能超过一个包的大小
    if (size > PKTBUF_BLK_SIZE)
    {
        dbg_ERROR(DBG_BUF, "size too big: %d > %d", size, PKTBUF_BLK_SIZE);
        return NET_ERR_SIZE;
    }

    // size最大也不能超过buf的最大长度
    if (size > buf->total_size)
    {
        dbg_ERROR(DBG_BUF, "size %d > total_size %d", size, buf->total_size);
        return NET_ERR_SIZE;
    }

    // 如果size还没有第一个块的size大，直接返回就好
    pktblk_t* first_blk = pktbuf_first_blk(buf);
    if (size < first_blk->size)
    {
        display_check_buf(buf);
        return NET_ERR_OK;
    }

    // 先把第一个块的数据拷到最前面
    // 先判断一下第一个块是不是从最前面开始的，如果是就不用拷贝了
    uint8_t* dest = first_blk->payload;
    if (first_blk->data != first_blk->payload)
    {
        for (int i = 0; i < first_blk->size; i++)
            *dest++ = first_blk->data[i];
        first_blk->data = first_blk->payload;
    }

    // 走到这就说明size一定比第一个块的size大，但是大多少不知道，接着看看去除第一个块还剩下多大，然后循环的把剩下的拷贝到第一个块
    pktblk_t* curr_blk = pktblk_blk_next(first_blk);
    int remain_size = size - first_blk->size;
    while (remain_size)
    {
        pktblk_t* pre_blk = pktblk_blk_pre(curr_blk);
        dest = pre_blk->payload + (uint8_t)pre_blk->size;
        // 先判断下一个块的大小和剩下的size哪个多，如果size多，就让curr_size=下一个块的大小，就相当于把下一个块全部搬到第一个块
        // 如果下一个块的大小多，就让curr_size=size，就相当于从下一个块搬一部分到上一个块
        int curr_size = (curr_blk->size > remain_size) ? remain_size : curr_blk->size;
        // 再判断一下上一个块剩下的大小和curr_size谁大，如果前者大，说明上一个块还够装，就让curr_size还等于curr_size
        // 如果curr_size大，说明上一个块不够装了，只能让上一个块装满，所以curr_size=上一个块剩下的大小
        curr_size = (curr_size < curr_blk_tail_free(pre_blk)) ? curr_size : curr_blk_tail_free(pre_blk);
        plat_memcpy(dest, curr_blk->data, curr_size);
        
        // 考完之后看看被考的块有没有空
        curr_blk->size -= curr_size;
        // 用来标识被考的块有没有考完，如果考完了就是0，没考完就是1
        int flag = 1;
        if (curr_blk->size != 0)
        {
            // 说明这个块还有数据没被考完，需要调整两个块
            pre_blk->size += curr_size;
            curr_blk->data += curr_size;
            remain_size -= curr_size;
        }else
        {
            // 说明curr_blk已经燃尽了，化作雪白的灰
            // 那么就直接把curr_blk释放，单独调整一下pre_blk就可以了
            flag = 0;
            pktblk_t* next_blk = pktblk_blk_next(curr_blk);
            nlist_remove(&buf->blk_list, &curr_blk->node);
            pktblock_free(curr_blk);
            curr_blk = next_blk;

            pre_blk->size += curr_size;
            remain_size -= curr_size;
        }

        // 接下来需要处理的一种情况是pre已经满了，但是curr还有数据需要考
        if (pre_blk->size == PKTBUF_BLK_SIZE && flag == 1)
        {
            // 看看curr剩下的数据能不能满足remain_size
            if (curr_blk->size < remain_size)
            {
                // 如果不能满足的话，就把curr的payload先搬到最前面来，然后再调整一下当前谁是curr_blk
                dest = curr_blk->payload;
                for (int i = 0; i < curr_blk->size; i++)
                    *dest++ = curr_blk->data[i];
                curr_blk->data = curr_blk->payload;

                curr_blk = pktblk_blk_next(curr_blk);
            }
            else
                remain_size = 0;
        }
    }
    display_check_buf(buf);
    return NET_ERR_OK;
}

/**
 * 重置包内指针，将指针指向包内的第一个块的起始位置
 * @param buf 需要被重置的包
 * @return err类型的返回值
 */
void pktbuf_reset_acc(pktbuf_t * buf)
{
    if (buf)
    {
        buf->curr_blk = pktbuf_first_blk(buf);
        buf->pos = 0;
        buf->blk_offset = buf->curr_blk ? buf->curr_blk->data : (uint8_t *)0;
    }
    else
        dbg_ERROR(DBG_BUF, "buf is empty");
}

/**
 * 从src内往当前指针除写入size字节的数据
 * @param buf 被写的包
 * @param src 写的数据源是哪
 * @param size 写多少个字节数
 * @return err类型的返回值
 */
net_err_t pktbuf_write (pktbuf_t * buf, uint8_t * src, int size)
{
    // src和size都不能为0
    if (!src || !size)
        return NET_ERR_PARAM;
    
    int remain_size = total_blk_remain(buf);
    // 写入的大小不能超出buf中剩余总空间的大小
    if (remain_size < size)
    {
        dbg_ERROR(DBG_BUF, "size error: %d < %d", remain_size, size);
        return NET_ERR_SIZE;
    }

    // 没太大的问题，开始往里面写入
    while (size)
    {
        int blk_size = curr_blk_remain(buf);

        int curr_copy_size = (size > blk_size) ? blk_size : size;
        plat_memcpy(buf->blk_offset, src, curr_copy_size);

        src += curr_copy_size;
        size -= curr_copy_size;

        move_forward(buf, curr_copy_size);
    }
    return NET_ERR_OK;
}

/**
 * 从包内读size个字节到dest
 * @param buf 被读的包
 * @param dest 读到哪去
 * @param size 读多少个字节数
 * @return err类型的返回值
 */
net_err_t pktbuf_read (pktbuf_t * buf, uint8_t * dest, int size)
{
    // dest和size都不能为0
    if (!dest || !size)
        return NET_ERR_PARAM;
    
    int remain_size = total_blk_remain(buf);
    // 读取的大小不能超出buf中剩余总空间的大小
    if (remain_size < size)
    {
        dbg_ERROR(DBG_BUF, "size error: %d < %d", remain_size, size);
        return NET_ERR_SIZE;
    }

    // 没太大的问题，开始往里面写入
    while (size)
    {
        // 先取到当前节点的剩余大小
        int blk_size = curr_blk_remain(buf);

        // 实际写入的大小不应该超过当前节点的剩余大小
        int curr_copy_size = (size > blk_size) ? blk_size : size;
        plat_memcpy(dest, buf->blk_offset, curr_copy_size);

        // 一次写入后，各个指针都需要修改
        dest += curr_copy_size;
        size -= curr_copy_size;

        // 把buf内的参数指向下一个块
        move_forward(buf, curr_copy_size);
    }
    return NET_ERR_OK;
}

/**
 * 设置包内的指针
 * @param buf 被设置的包
 * @param offset 设置的指针偏移是多少
 * @return err类型的返回值
 */
net_err_t pktbuf_seek (pktbuf_t * buf, int offset)
{
    if (buf->pos == offset)
        return NET_ERR_OK;

    // 偏移不能小于0或大于buf的总大小   
    if (offset < 0 || buf->total_size <= offset)
        return NET_ERR_SIZE;

    int move_bytes;
    // 看看offset和当前指针谁在前谁在后
    if (offset < buf->pos)
    {
        // offset在前，那么我们要从头节点开始遍历，找到offset指向的地方，这里先把buf的参数清空，遍历后面做
        buf->curr_blk = pktbuf_first_blk(buf);
        buf->blk_offset = buf->curr_blk->data;
        buf->pos = 0;

        move_bytes = offset;
    }else
    {
        // offset在后，那么我们只需要从当前节点开始遍历就好
        move_bytes = offset - buf->pos;
    }

    // 开始遍历
    while (move_bytes)
    {
        // 这部分和上一个写入的函数有异曲同工之妙
        int reamin_size = curr_blk_remain(buf);
        int curr_move_size = (move_bytes > reamin_size) ? reamin_size : move_bytes;

        move_forward(buf, curr_move_size);
        move_bytes -= curr_move_size;
    }
    return NET_ERR_OK;
}

/**
 * 将src块当前块指针指向位置的后size字节拷贝到dest块当前块指针指向位置的后size字节
 * 注意，拷贝是从当前的块指针进行的，拷贝前需要先设置块指针的位置，拷贝完成后当前的块指针也会发生变化
 * @param dest 拷贝的目标块
 * @param offset 被拷贝的块
 * @param size 拷贝的字节数
 * @return err类型的返回值
 */
net_err_t pktbuf_copy (pktbuf_t * dest, pktbuf_t * src, int size)
{
    // size是从当前指针拷贝的大小，理应不能超过dest和src剩余的空间
    if (size > total_blk_remain(dest) || size > total_blk_remain(src))
        return NET_ERR_SIZE;

    // 开始循环的拷贝
    while (size)
    {
        // 先计算在该轮循环中需要拷贝的大小
        int dest_remain_size = curr_blk_remain(dest);
        int src_remain_size = curr_blk_remain(src);
        int copy_size = (dest_remain_size > src_remain_size) ? src_remain_size : dest_remain_size;
        copy_size = (copy_size > size) ? size : copy_size;
        
        // 拷贝
        plat_memcpy(dest->blk_offset, src->blk_offset, copy_size);

        // 调整dest和src中的块指针
        move_forward(dest, copy_size);
        move_forward(src, copy_size);

        size -= copy_size;
    }
    return NET_ERR_OK;
}

/**
 * 将src块当前块指针指向位置的后size字节拷贝到dest块当前块指针指向位置的后size字节
 * 注意，填充是从当前的块指针进行的，填充前需要先设置块指针的位置，填充完成后当前的块指针也会发生变化
 * @param buf 被填充的目标包
 * @param v 填充成的字节
 * @param size 填充的字节数
 * @return err类型的返回值
 */
net_err_t pktbuf_fill (pktbuf_t * buf, uint8_t v, int size)
{
    // size都不能为0
    if ( !size)
        return NET_ERR_PARAM;
    
    int remain_size = total_blk_remain(buf);
    // 写入的大小不能超出buf中剩余总空间的大小
    if (remain_size < size)
    {
        dbg_ERROR(DBG_BUF, "size error: %d < %d", remain_size, size);
        return NET_ERR_SIZE;
    }

    // 没太大的问题，开始往里面写入
    while (size)
    {
        int blk_size = curr_blk_remain(buf);

        int curr_fill_size = (size > blk_size) ? blk_size : size;
        plat_memset(buf->blk_offset, v, curr_fill_size);

        size -= curr_fill_size;
        move_forward(buf, curr_fill_size);
    }
    return NET_ERR_OK;
}

uint16_t pktbuf_checksum16 (pktbuf_t * buf, int len, uint32_t pre_sum, int complement)
{
    dbg_assert(buf->res != 0, "buf ref == 0");

    int remain_size = total_blk_remain(buf);  // buf.toal_size
    if (remain_size < len) {
        dbg_WARNING(DBG_BUF, "size too big");
        return 0;
    }

    uint32_t sum = pre_sum;
    while (len > 0) {
        int blk_size = curr_blk_remain(buf);
        int curr_size = (blk_size > len) ? len : blk_size;

        sum = checksum16(buf->blk_offset, curr_size, sum, 0);

        move_forward(buf, curr_size);
        len -= curr_size;
    }

    return complement ? (uint16_t)~sum : (uint16_t)sum;
}