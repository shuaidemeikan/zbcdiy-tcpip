/**
 * 整个socket接口这一块有一些有趣的处理，我写在raw模块这里，因为raw本身有一些独特的处理
 * 1、在此前协议栈内部的模块，涉及到内存的分配，都是使用mblock来分配的，但是实际上这里不需要用mblock分配
 * 因为socket接口的所有模块都是用的exmsg来调用的，exmsg本身就会保证同一时间内只有一个线程可以执行这一块的代码
 * 所以这一块其实是单线程的，使用mblock反而会因为对锁的多余处理而影响效率
 * 但是使用mblock并不是完全不好的，如果不是用mblock，分配和释放等等操作都需要自己重写
 * socket结构比较灵活，重写也无可厚非，所以socket结构没有使用mblock来分配
 * 2、raw结构实质上是给sock结构加了几个字段，所以在初始化和调用的时候，其实可以直接把raw结构当做sock结构来处理
 */
#include "raw.h"
#include "debug.h"
#include "mblock.h"
#include "sock.h"

#define RAW_MAX_NR      10

static raw_t raw_tbl[RAW_MAX_NR];
static mblock_t raw_mblock;
static nlist_t raw_list;

net_err_t raw_init (void)
{
    dbg_info(DBG_RAW, "raw init");

    nlist_init(&raw_list);
    mblock_init(&raw_mblock, raw_tbl, sizeof(raw_t), RAW_MAX_NR, NLOCKER_NONE);
    dbg_info(DBG_RAW, "done");
    return NET_ERR_OK;
}

/**
 * 创建一个raw结构
 * @param str 字符串类型的地址
 * @return 转换成的32位数据
 */
sock_t* raw_create (int family, int protocol)
{
    // 创建用于raw操作的函数
    static const sock_opt_t raw_ops = {
        .sendto = raw_create,
    };

    // 申请一个rwa
    raw_t* raw = mblock_alloc(&raw_mblock, -1);
    if (!raw)
    {
        dbg_error(DBG_RAW, "no raw sock");
        return (sock_t*)0;
    }

    // 把这个raw结构当做socket结构初始化
    net_err_t err = sock_init((sock_t*)raw, family, protocol, &raw_ops);
    if (err < 0)
    {
        dbg_error(DBG_RAW, "create raw failed");
        mblock_free(&raw_mblock, raw);
        return (sock_t*)0;
    }
    nlist_insert_last(&raw_list, &raw->base.node);
    return (sock_t*)raw;
}