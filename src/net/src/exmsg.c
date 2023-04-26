#include "exmsg.h"
#include "sys_plat.h"
#include "debug.h"
#include "fixq.h"
#include "mblock.h"

// 用于保存消息队列具体内容的内存空间
static void* msg_tbl[EXMSG_MSG_CNT];
// 消息队列本体
static fixq_t msg_queue;
// 用于临时接收数据的链表的内存
static exmsg_t msg_buffer[EXMSG_MSG_CNT];
// 用于临时接受数据的链表本体
static mblock_t msg_block;

net_err_t exmsg_init(void)
{
    // 先初始化创建一个消息队列
    dbg_info(DBG_MSG, "exmsg init...");

    // 初始化消息队列
    net_err_t err = fixq_init(&msg_queue, msg_tbl, EXMSG_MSG_CNT, EXMSG_LOCKER);
    if (err < 0)
    {
        dbg_ERROR(DBG_MSG, "fixq init failed!");
        return err;
    }

    // 初始化用于临时保存消息的链表
    err = mblock_init(&msg_block, msg_buffer, sizeof(exmsg_t), EXMSG_MSG_CNT, EXMSG_LOCKER);
    if (err < 0)
    {
        dbg_ERROR(DBG_MSG, "mblock init failed!");
        return err;
    }

    //如果能走到这一步还不return，那就说明消息队列初始化成功了
    dbg_info(DBG_MSG, "init done.");
    return NET_ERR_OK;
}

/**
 * 接收网卡线程的数据包
 * @return err类型的返回值
 */
net_err_t exmsg_netif_in(netif_t* netif)
{
    // 先从链表里拿一个内存块来临时存一下消息
    exmsg_t* msg = mblock_alloc(&msg_block, -1);
    if (!msg)
    {
        dbg_WARNING(DBG_MSG, "no free block.");
        return NET_ERR_MEM;
    }

    // 测试性的放一些数据在里面
    static int id = 0;
    msg->type = NET_EXMSG_NETIF_IN;
    msg->id = id++;

    // 把刚刚临时存的信息放到消息队列里
    net_err_t err = fixq_send(&msg_queue, msg, -1);
    if (err < 0)
    {
        dbg_WARNING(DBG_MSG, "fixq full.");
        // 如果发生错误，需要把上面拿到的链表的节点释放掉
        mblock_free(&msg_block, msg);
        return err;
    }

    // 如果能走到这一步，说明上面都没出问题，直接返回ok就好
    return NET_ERR_OK;
}

static void work_thread(void* arg)
{
    plat_printf("exmsg is running...\n");
    while(1)
    {
        // 从消息队列中取出数据，如果消息队列中没有数据，那么该线程会卡在这卡着
        exmsg_t * msg = (exmsg_t *)fixq_recv(&msg_queue, 0);
        // 模拟对取出的数据进行处理
        plat_printf("recv a msg type: %d, id: %d\n", msg->type, msg->id);
        // 处理完了需要把临时用来接收的链表节点释放回链表
        mblock_free(&msg_block, msg);
    }
}

net_err_t exmsg_start(void)
{
    sys_thread_t thread = sys_thread_create(work_thread, (void*)0);
    if (thread == SYS_THREAD_INVALID)
    {
        return NET_ERR_SYS;
    }
    return NET_ERR_OK;
}