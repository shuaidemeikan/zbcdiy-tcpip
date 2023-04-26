#ifndef FIXQ_H
#define FIXQ_H

#include "sys.h"
#include "nlocker.h"
// size表示该队列的最大长度，cnt表示队列当前的长度
// in，out分别表示当前读，写指针
// buf表示当前用于当队列的内存块
typedef struct _fixq_t
{
    int size;
    int in, out, cnt;
    void** buf;

    nlocker_t locker;
    sys_sem_t recv_sem;     // 负责接受的信号量（队列里当前可读的数量）
    sys_sem_t send_sem;     // 负责发送的信号量（队列里当前可写的数量）
}fixq_t;

net_err_t fixq_init(fixq_t* q, void** buf, int size, nlocker_type_t type);
net_err_t fixq_send(fixq_t* q, void* msg, int tmo);
void* fixq_recv(fixq_t* q, int tmo);
void fixq_destory(fixq_t* q);
int fixq_count(fixq_t* q);
#endif // !FIXQ_H