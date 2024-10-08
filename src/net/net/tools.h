﻿#ifndef TOOLS_H
#define TOOLS_H

#include "stdint.h"
#include "net_cfg.h"
#include "net_err.h"
#include "pktbuf.h"

static inline uint16_t swap_u16 (uint16_t v)
{
    uint16_t r = ((v & 0xFF) << 8) | ((v >> 8) & 0xFF);
    return r;
}

static inline uint32_t swap_u32 (uint32_t v)
{
    uint32_t r = ((v & 0xff) << 24)| (((v >> 8) & 0xff) << 16)| (((v >> 16) & 0xff) << 8) | ((v >> 24) & 0xff);
    
    return r;
}

#if NET_ENDIAN_LITTLE
// x代表和c标准库区分，h代表host，to就是to，n代表network，s代表16位，l代表32位
#define x_htons(v)      swap_u16(v)
#define x_ntohs(v)      swap_u16(v)
#define x_htonl(v)      swap_u32(v)
#define x_ntohl(v)      swap_u32(v)
#else
#define x_htons(v)
#define x_ntohs(v)
#define x_htonl(v)
#define x_ntohl(v)
#endif

net_err_t tools_init (void);

uint16_t checksum16 (uint32_t offset, void * buf, uint16_t len, uint32_t pre_sum, int complement);
uint16_t checksum_peso(const uint8_t * src_ip, const uint8_t* dest_ip, uint8_t protocol, pktbuf_t * buf);
#endif 