#ifndef _SOCKET_H
#define _SOCKET_H

#include <stdint.h>
#include "ipv4.h"
#include "sock.h"

#undef INADDR_ANY
#define INADDR_ANY              (uint32_t)0x00000000

#undef AF_INET
#define AF_INET         2  

#undef SOCK_RAW
#define SOCK_RAW    0
#undef SOCK_DGRAM
#define SOCK_DGRAM  1

#undef IPPROTO_ICMP
#define IPPROTP_ICMP    1
#undef IPPROTO_UDP
#define IPPROTO_UDP     17

#undef SOL_SOCKET
#define SOL_SOCKET      0

#undef SO_RCVTIMEO
#define SO_RCVTIMEO     1
#undef SO_SNDTIMEO
#define SO_SNDTIMEO     2

/*
    目前协议栈内的ip地址有以下几种:
    1、x_in_addr:承载的是一个ipv4的地址，使用addr_array[]可依次访问每个段，使用s_addr可一次性拿出所有位数
    2、x_sockaddr_in:x_sockaddr的ipv4特殊实现，封装了x_in_addr类型，加上了长度，协议，端口和填充字段，使用起来更为直接
    3、x_sockaddr:x_sockaddr_in的原始实现，将端口和填充字段结合为一个字段，这个字段并不一定填端口，更为灵活
    4、uint32:单纯的32位地址，其中每8位保存了一个段
    5、char*:单纯的字符串类型地址
*/
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
    char sin_zero[8];               // 填充字段，一般全为0
};

struct x_timeval
{
    int tv_sec;
    int tv_usec;
};

int x_socket(int family, int type, int protocol);
ssize_t x_sendto(int s, const void* buf, size_t len, int flags, const struct x_sockaddr* dest, x_socklen_t dest_len);
ssize_t x_recvfrom(int s, void* buf, size_t len, int flags, const struct x_sockaddr* src, x_socklen_t* src_len);
int x_setsockopt(int s, int level, int optname, const char* optval, int len);
int x_close (int s);
#endif 