#include "timer.h"
#include "debug.h"
#include "sys_plat.h"



static nlist_t timer_list;

#if DBG_DISP_ENABLED(DBG_TIMER)
static void display_timer_list (void)
{
    plat_printf("--------------timer list --------------\n");
    nlist_node_t* node;
    int index = 0;
    nlist_for_each(node, &timer_list)
    {
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);
        plat_printf("%d: %s, period=%d, curr: %d ms, reload: %d ms \n", index++, timer->name, timer->flags & NET_TIMER_RELOAD ? 1 : 0, timer->curr, timer->reload); 
    }
    plat_printf("____________timer list end ---------------\n");
}
#else
#define display_timer_list()
#endif

net_err_t net_timer_init (void)
{
    dbg_info(DBG_TIMER, "timer init");

    nlist_init(&timer_list);

    dbg_info(DBG_TIMER, "timer init done");
    return NET_ERR_OK;
}

static void insert_timer(net_timer_t* timer)
{
    nlist_node_t* node;
    nlist_for_each(node, &timer_list)
    {
        net_timer_t* curr = nlist_entry(node, net_timer_t, node);
        // 当新加的节点大于当前遍历到的节点时，说明新加的节点要放在后面，那么需要减去遍历到的节点的curr，然后往后面插
        if (timer->curr > curr->curr )
            timer->curr -= curr->curr;
        // 如果两者相等，那么直接把后加入的插在后面，并且清空curr值
        else if (timer->curr == curr->curr)
        {
            timer->curr = 0;
            nlist_insert_after(&timer_list, node, &timer->node);
            return;
        // 如果都不满足，那就是小于，小于的情况要把这个新加的节点放在当前遍历到的节点的前面
        }else
        {
            // 放前面的话，得让当前遍历到的节点减去新加入的节点的curr值
            curr->curr -= timer->curr;

            // 需要检测当前节点前面有没有节点，因为我们需要把这个节点插在当前节点前一个节点的后面
            // 如果前面没有节点的话，我们去拿当前节点的前一个节点会拿到null，null当然不能直接把链表串起来
            // 所以当前面没有节点的话，我们直接调first插入就好
            nlist_node_t* pre = nlist_node_pre(node);
            if (pre)
            {
                nlist_insert_after(&timer_list, pre, &timer->node);
                return;
            }else
            {
                nlist_insert_first(&timer_list, &timer->node);
                return;
            }
        }
    }
    // 不论是相等还是小于，都在遍历里完成了插入，然后返回了，所以如果走到这，就是减完了链表内所有节点的curr还是大于，那么直接插到尾部就好
    nlist_insert_last(&timer_list, &timer->node);
}

/**
 * 往定时器列表里添加一个定时器
 * @param timer 添加的定时器
 * @param name 定时器名
 * @param proc 定时器执行的函数
 * @param arg 定时器执行的函数需要的参数
 * @param ms 定时时长
 * @param flags 标志寄存器，用来控制定时器是否重载
 * @return err类型的返回值
 */
net_err_t net_timer_add (net_timer_t* timer, const char* name ,timer_proc_t proc, void* arg, int ms, int flags)
{
    dbg_info(DBG_TIMER, "insert timer: %s", name);
    plat_strncpy(timer->name, name, TIMER_NAME_SIZE);
    timer->name[TIMER_NAME_SIZE - 1] = '\0';
    timer->reload = ms;
    timer->curr = ms;
    timer->proc = proc;
    timer->arg = arg;
    timer->flags = flags;
    
    insert_timer(timer);
    //nlist_insert_last(&timer_list, &timer->node);

    display_timer_list();
    return NET_ERR_OK;
}

void net_timer_remove (net_timer_t* timer)
{
    dbg_info(DBG_TIMER, "remove timer: %s", timer->name);
    nlist_node_t* node;
    nlist_for_each(node, &timer_list)
    {
        if (&timer->node != node)
            continue;
        else
        {
            net_timer_t* curr = nlist_entry(node, net_timer_t, node);
            nlist_node_t* next = nlist_node_next(node);
            if (next)
            {
                net_timer_t* next_timer = nlist_entry(next, net_timer_t, node);
                next_timer->curr += curr->curr;
            }
            nlist_remove(&timer_list, &timer->node);
            break;
        }
    }
    display_timer_list();
}

net_err_t net_timer_check_tmo (int diff_ms)
{
    display_timer_list();
    static nlist_t timeout_timer;
    nlist_init(&timeout_timer);

    nlist_node_t* node = nlist_first(&timer_list);
    while (node)
    {
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);
        if (timer->curr > diff_ms)
        {
            timer->curr -= diff_ms;
            break;
        }
        else
        {
            node = nlist_node_next(node);         // 更新node节点
            diff_ms -= timer->curr;                             // 更新diff_ms时间
            //timer->curr = 0;
            nlist_remove(&timer_list, &timer->node);             // 将该节点从定时器列表移除
            nlist_insert_last(&timeout_timer, &timer->node);     // 将该节点插入到超市列表里
            
        }
    }

    // 扫描完了，此时所有超时的定时器都被扫描出来了，遍历一下超时列表
    node = nlist_first(&timeout_timer);
    while (node)
    {
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);
        timer->proc(timer, timer->arg);
        
        node = nlist_node_next(node);

        if (timer->flags & NET_TIMER_RELOAD)
        {
            timer->curr = timer->reload;
            insert_timer(timer);
        }
        
    }

    display_timer_list();
    return NET_ERR_OK;
}

int net_timer_first_tmo (void)
{
    nlist_node_t* node = nlist_first(&timer_list);
    if (node)
    {
        net_timer_t* timer = nlist_entry(node, net_timer_t, node);
        return timer->curr;
    }
    return 0;
}