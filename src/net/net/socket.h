#ifndef _SOCKET_H
#define _SOCKET_H

#include <stdint.h>
#include "ipv4.h"

#undef INADDR_ANY
#define INADDR_ANY              (uint32_t)0x00000000

#undef AF_INET
#define AF_INET         2  

#undef SOCK_RAW
#define SOCK_RAW    0

#undef IPPROTO_ICMP
#define IPPROTP_ICMP    0

struct x_in_addr
{
    union 
    {
        struct 
        {
            uint8_t addr0;
            uint8_t addr1;
            uint8_t addr2;
            uint8_t addr3;
        };
        uint8_t addr_array[IPV4_ADDR_SIZE];

        #undef s_addr
        uint32_t s_addr;
    };
};

struct x_sockaddr
{
    uint8_t sin_len;
    uint8_t sin_family;
    uint8_t sa_data[14];
};

struct x_sockaddr_in
{
    uint8_t sin_len;
    uint8_t sin_family;
    uint8_t sin_port;
    struct x_in_addr sin_addr;
    char sin_zero[8];
};

int x_socket(int family, int type, int protocol);

#endif // ! 