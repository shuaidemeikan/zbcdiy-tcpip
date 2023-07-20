#ifndef TIMER_H
#define TIMER_H

#include "net_cfg.h"
#include "net_err.h"
#include "nlist.h"

#define NET_TIMER_RELOAD        (1 << 0)

struct _net_timer_t;
typedef void (*timer_proc_t) (struct _net_timer_t* timer, void* arg);

typedef struct _net_timer_t
{
    char name[TIMER_NAME_SIZE];     // 定时器名
    int flags;                      // 是否允许定时器重载
    int curr;                       // 用于将定时器排序的值，有获取当前计数值的功能，但是需要转换
    int reload;                     // 定时器重载后计数值
    timer_proc_t proc;              // 到时间后执行的函数
    void* arg;                      // 定时器附带的参数
    nlist_node_t node;              
}net_timer_t;

net_err_t net_timer_init (void);
net_err_t net_timer_add (net_timer_t* timer, const char* name ,timer_proc_t proc, void* arg, int ms, int flags);
void net_timer_remove (net_timer_t* timer);
net_err_t net_timer_check_tmo (int diff_ms);
int net_timer_first_tmo (void);
#endif