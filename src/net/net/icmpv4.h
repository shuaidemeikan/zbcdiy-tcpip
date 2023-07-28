#ifndef ICMPV4_H
#define ICMPV4_H

#include "netif.h"
#include "pktbuf.h"
#include "ipv4.h"

#define ICMPv4_ECHO_REQUEST     8
#define ICMPv4_ECHO_REPLY       0

#define ICMPv4_ECHO             0

#pragma pack(1)
typedef struct _icmpv4_hdr_t
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum16;
}icmpv4_hdr_t;

typedef struct _icmpv4_pkt_t
{
    icmpv4_hdr_t hdr;
    union
    {
        uint32_t reverse;
    };
    uint8_t data[1];
}icmpv4_pkt_t;
#pragma pack()

net_err_t icmpv4_init (void);
net_err_t icmpv4_in (ipaddr_t* src_ip, ipaddr_t* netif_ip, pktbuf_t* buf);

#endif // !