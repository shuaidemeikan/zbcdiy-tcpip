#ifndef ARP_H
#define ARP_H

#include "ipaddr.h"
#include "ether.h"
#include "pktbuf.h"

#define ARP_HW_ETHER    1
#define ARP_REQUEST     1
#define ARP_REPLAY      2

#pragma pack(1)
typedef struct _arp_pkt_t
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hwlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_hwaddr[ETHER_HWA_SIZE];
    uint8_t sender_paddr[IPV4_ADDR_SIZE];
    uint8_t target_hwaddr[ETHER_HWA_SIZE];
    uint8_t target_paddr[IPV4_ADDR_SIZE];
}arp_pkt_t;
#pragma pack(1)

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

    int tmo;
    int retry;

    nlist_node_t node;
    nlist_t buf_list;
    netif_t* netif;

}arp_entry_t;

net_err_t arp_init (void);
net_err_t arp_make_rquest(netif_t* netif, const ipaddr_t* dest);
net_err_t arp_make_gratuitous(netif_t* netif);
net_err_t arp_in (netif_t* netif, pktbuf_t* buf);

#endif