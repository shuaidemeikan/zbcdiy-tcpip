#ifndef PROTOCOL_H
#define PROTOCOL_H

#define NET_PORT_EMPTY      0

typedef enum _protocol_t
{
    NET_PROTOCOL_ARP = 0x0806,
    NET_PROTOCOL_IPV4 = 0x0800,
    NET_PROTOCOL_ICMPv4 = 1,
    NET_PROTOCOL_UDP = 0X11,
    NET_PROTOCOL_TCP = 0X6,
}protocol_t;

#endif