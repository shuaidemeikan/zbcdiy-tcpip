﻿#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include "net_err.h"
#include "net_cfg.h"
#include "netif.h"
#include "nlist.h"

#define IPV4_ADDR_SIZE      4
#define NET_VERSION_IPV4    4
#define NET_IP_DEFAULT_TTL  64

#pragma pack(1)
typedef struct _ipv4_hdr_t
{
    union
    {
        struct 
        {
            #if NET_ENDIAN_LITTLE
            uint16_t shdr : 4;
            uint16_t version : 4;
            uint16_t tos : 8;
            #else
            uint16_t version : 4;
            uint16_t shdr : 4;
            uint16_t tos : 8;
            #endif
        };
        uint16_t shdr_all;
    };
    uint16_t total_len;
    uint16_t id;
    union 
    {
        struct 
        {
            #if NET_ENDIAN_LITTLE
            uint16_t frag_offset : 13;          // 分片偏移
            uint16_t more : 1;                  // 是否还有更多的分片
            uint16_t disable : 1;               // 是否允许分片
            uint16_t reversed : 1;              // 占位符
            #else
            uint16_t reversed : 1;
            uint16_t disable : 1;
            uint16_t more : 1;
            uint16_t frag_offset : 13;
            #endif
        };
        uint16_t frag_all;
        
    };
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_checksum;
    uint8_t src_ip[IPV4_ADDR_SIZE];
    uint8_t dest_ip[IPV4_ADDR_SIZE];
}ipv4_hdr_t;

typedef struct _ipv4_pkt_t
{
    ipv4_hdr_t hdr;
    uint8_t data[1];
}ipv4_pkt_t;

#pragma pack()

typedef struct _ip_frag_t
{
    ipaddr_t ip;               // 标识这个分片组都是从哪个ip收到的数据包
    uint16_t id;                // 分片id
    int tmo;                    // 等待新分片的超时时间
    nlist_t buf_list;
    nlist_node_t node;
}ip_frag_t;

net_err_t ipv4_init (void);
net_err_t ipv4_in (netif_t* netif, pktbuf_t* buf);
net_err_t ipv4_out(uint8_t protocol, ipaddr_t* dest, ipaddr_t* src, pktbuf_t* buf);

static inline int ipv4_hdr_size (ipv4_pkt_t* pkt)
{
    return pkt->hdr.shdr * 4;
}

static inline void ipv4_set_hdr_size (ipv4_pkt_t* pkt, int len)
{
    pkt->hdr.shdr = len / 4;
}

#endif