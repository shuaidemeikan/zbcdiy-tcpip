#ifndef _RAW_H
#define _RAW_H

#include "sock.h"
#include "net_err.h"

typedef struct _raw_t
{
    sock_t base;
}raw_t;

net_err_t raw_init (void);
sock_t* raw_create (int family, int protocol);
#endif