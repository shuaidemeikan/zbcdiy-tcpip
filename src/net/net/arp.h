#ifndef ARP_H
#define ARP_H

#include "ipaddr.h"
#include "ether.h"
#include "pktbuf.h"

typedef struct _arp_entry_t
{
    uint8_t paddr[IPV4_ADDR_SIZE];
    uint8_t hwaddr[ETHER_HWA_SIZE];

    enum
    {
        NET_APR_FREE,                   // 该表项完全无用
        NET_ARP_WATTING,                // 该表项正在等待解析的回应
        NET_ARP_RESOLVED,               // 该表项已经被回应且正确的存储
    }state;

    nlist_node_t* node;
    nlist_t buf_list;
    nlist_t* netif;

}arp_entry_t;

net_err_t arp_init (void);

#endif