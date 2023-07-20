#include "exmsg.h"
#include "sys_plat.h"
#include "debug.h"
#include "fixq.h"
#include "mblock.h"
#include "sys.h"
#include "timer.h"

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

    msg->type = NET_EXMSG_NETIF_IN;
    msg->netif.netif = netif;

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

/**
 * 大多数包的处理函数
 * @param msg 要被处理的包的类型，包来自哪张网卡，这个线程根据这个去对应的网卡的in_q队列中取数据
 */
static net_err_t do_netif_in(exmsg_t* msg)
{
    netif_t* netif = msg->netif.netif;

    pktbuf_t* buf;
    while (buf = netif_get_in(netif, -1))
    {
        dbg_info(DBG_MSG, "recv a packet");

        if (netif->link_layer)
        {
            net_err_t err = netif->link_layer->in(netif, buf);
            if (err < 0)
            {
                // 秉持一个原则，当出错时，由这里返回，当不出错时，让最终处理的函数自己返回
                pktbuf_free(buf);
                dbg_WARNING(DBG_MSG, "netif in failed, error = %d", err);
            }
        }else 
            // 同样，netif内的link_layer没有的话，就没办法对这个包进行处理，应该直接返回
            pktbuf_free(buf);
    }
    return NET_ERR_OK;
}

/**
 * 作用很多，目前主要做的是：
 * 当有人调exmsg_netif_in往全局消息队列内送数据的时候，判断一下数据类型然后扔给对应的处理函数，没有数据就一直睡
 */
static void work_thread(void* arg)
{
    plat_printf("exmsg is running...\n");
    net_time_t time;
    sys_time_curr(&time);

    while(1)
    {
        // 从消息队列中取出数据，如果消息队列中没有数据，那么该线程会卡在这卡着
        int first_tmo = net_timer_first_tmo();
        exmsg_t * msg = (exmsg_t *)fixq_recv(&msg_queue, first_tmo);
        if (msg)
        {
            dbg_info(DBG_MSG, "recv a msg %p: %d\n", msg, msg->type);
            switch (msg->type)
            {
            case NET_EXMSG_NETIF_IN:
                do_netif_in(msg);
                break;
            
            default:
                break;
            }
            // 处理完了需要把临时用来接收的链表节点释放回链表
            mblock_free(&msg_block, msg);
        }
        
        int diff_ms = sys_time_goes(&time);
        net_timer_check_tmo(diff_ms);
        //net_timer_check_tmo(1000);
    }
}

/**
 * 协议栈exmsg的启动，工作线程在这里被创建
 * @return err类型的返回值
 */
net_err_t exmsg_start(void)
{
    sys_thread_t thread = sys_thread_create(work_thread, (void*)0);
    if (thread == SYS_THREAD_INVALID)
    {
        return NET_ERR_SYS;
    }
    return NET_ERR_OK;
}