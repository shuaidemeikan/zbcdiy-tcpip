#include "fixq.h"
#include "debug.h"

/**
 * 初始化消息队列
 * @param q 待初始化的消息队列
 * @param buf 消息队列占用的内存
 * @param size 消息队列的大小
 * @param type 消息队列所用的锁的类型
 * @return err类型的返回值
 */
net_err_t fixq_init(fixq_t* q, void** buf, int size, nlocker_type_t type)
{
    // 基础的初始化
    q->buf = buf;
    q->size = size;
    q->in = q->out = q->cnt = 0;

    // 这里我们先将信号量默认的设置为创建失败，这样方便后续判断
    q->send_sem = SYS_SEM_INVALID;
    q->recv_sem = SYS_SEM_INVALID;

    // 初始化一个锁，但是这个锁可能拿不到，所以用err接一下
    net_err_t err = nlocker_init(&q->locker, type);
    if (err < 0)
    {
        // 锁初始化失败，直接返回err
        dbg_ERROR(DGB_QUEUE, "init locker failed.");
        return err;
    }

    // 接下来拿信号量
    // 发送的信号量（往队列里写），由于队列在初始化，内部是空的，全部都可以拿来存，所以数量应该是size
    q->send_sem = sys_sem_create(size);
    if (q->send_sem == SYS_SEM_INVALID)
    {
        // 同样，信号量也可以能初始化失败
        dbg_ERROR(DGB_QUEUE, "init locker failed.");
        // 按理来说这里应该直接return，但是由于初始化失败，我们应该释放上面拿到的锁，所以我们跳转到一个地方去统一的处理失败
        err = NET_ERR_SYS;
        goto init_failed;
    }

    // 接收的信号量（从队列里出去），由于队列在初始化，内部是空的，里面没有一个东西，所以数量应该是0
    q->recv_sem = sys_sem_create(0);
    if (q->recv_sem == SYS_SEM_INVALID)
    {
        // 同样，信号量也可以能初始化失败
        dbg_ERROR(DGB_QUEUE, "init locker failed.");
        // 按理来说这里应该直接return，但是由于初始化失败，我们应该释放上面拿到的锁，所以我们跳转到一个地方去统一的处理失败
        err = NET_ERR_SYS;
        goto init_failed;
    }

    // 如果能走到这一步，那就说明一切ok，所有初始化都正确的拿到了东西，直接返回ok
    return NET_ERR_OK;
init_failed:
    if (q->send_sem != SYS_SEM_INVALID)
        // send_sem被成功的初始化，说明问题出在别的地方，但是我们得先把正确拿到的send_sem释放
        sys_sem_free(q->send_sem);
    if (q->recv_sem != SYS_SEM_INVALID)
        // 同上
        sys_sem_free(q->recv_sem);

    // 销毁锁并返回
    nlocker_destroy(&q->locker);
    return err;
}

/**
 * 往消息队列里存一个数据
 * @param q 待被存的消息队列
 * @param msg 被存的消息的本体
 * @param tmo 等待的时间，tmo=0则说明一直等，tmo<0表述忽视信号量，不等
 * @return err类型的返回值
 */
net_err_t fixq_send(fixq_t* q, void* msg, int tmo)
{
    // 对一个共享数据进行读写，需要上锁
    nlocker_lock(&q->locker);
    // tmo小于零说明不需要等，q的cnt是当前消息队列内存的数量，size是最大数量
    // 所以如果当前的数量大于等于最大数量，那么就说明消息队列内已经没有多余的空间了
    // 即不能等，又没有多余的空间，这里直接返回一个错误就ok
    if ((tmo < 0) && (q->cnt >= q->size))
    {
        nlocker_unlock(&q->locker);
        return NET_ERR_FULL;
    }
    nlocker_unlock(&q->locker);

    // 拿信号量
    if (sys_sem_wait(q->send_sem, tmo) < 0)
    {
        // 没拿到，返回一个超时的错误
        return NET_ERR_TMO;
    }

    // 已经拿到信号量了，开始对消息队列进行操作
    nlocker_lock(&q->locker);
    // 从q->in的位置往q->buf里写
    q->buf[q->in++] = msg;
    // 判断一下q->in的位置，如果超过了队列的最大长度，那么应该从头再开始写
    if (q->in >= q->size)
        q->in = 0;
    // 每次写完之后当前队列内的数量都要++
    q->cnt++;
    nlocker_unlock(&q->locker);

    // 队列里可读的信号量+1
    sys_sem_notify(q->recv_sem);
    return NET_ERR_OK;
}

/**
 * 从消息队列里拿一个数据包
 * @param q 待被读取的消息队列
 * @param tmo 等待的时间，tmo=0则说明一直等，tmo<0表述忽视信号量，不等
 * @return 从消息队列里拿到的数据包
 */
void* fixq_recv(fixq_t* q, int tmo)
{
    nlocker_lock(&q->locker);
    // !q->cnt表示当前消息队列里没有东西，tmo小于零表示不等
    // 消息队列没有东西，又不愿意等，那么就只能返回一个0表示错误了
    if (!q->cnt && (tmo <0))
    {
        nlocker_unlock(&q->locker);
        return (void*)0;
    }
    nlocker_unlock(&q->locker);

    // 拿信号量
    if (sys_sem_wait(q->recv_sem, tmo) < 0)
    {
        return (void*)0;
    }

    // 走到这说明信号量拿到了，从消息队列里拿一个数据包出来返回
    nlocker_lock(&q->locker);
    void* msg = q->buf[q->out++];
    if (q->out >= q->size)
        // out是拿数据包的指针，如果out大过buf就需要把out指回起点，就像一个圆一样
        q->out = 0;
    // 拿掉了一个数据包，消息队列内的数据包数量应该--
    q->cnt--;
    nlocker_unlock(&q->locker);

    // 拿掉了一个数据包，往里写的信号量应该+1
    sys_sem_notify(q->send_sem);
    return msg;
}

/**
 * 销毁消息队列
 * @param q 待被销毁的消息队列
 */
void fixq_destory(fixq_t* q)
{
    nlocker_destroy(&q->locker);
    sys_sem_free(q->recv_sem);
    sys_sem_free(q->send_sem);
}

/**
 * 获得消息队列内已有的数据包数量
 * @param q 待被计数的消息队列
 * @return 消息队列内已有的数据包数量
 */
int fixq_count(fixq_t* q)
{
    nlocker_lock(&q->locker);
    int count = q->cnt;
    nlocker_unlock(&q->locker);
    return count;
}