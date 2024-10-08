﻿#ifndef NET_API_H
#define NET_API_H

#include "tools.h"
#include "socket.h"

char* x_inet_ntoa (struct x_in_addr in);
uint32_t x_inet_addr (const char* str);
int x_inet_pton (int family, const char* strptr, void* addrptr);
const char* x_inet_ntop (int family, const void* addrptr, char* strptr, size_t len);

#undef htons
#define htons(v)        x_htons(v)

#undef ntohs
#define ntohs(v)        x_ntohs(v)

#undef htonl
#define htonl(v)        x_htonl(v)

#undef ntohl
#define ntohl(v)        x_ntohl(v)

#define inet_ntoa(in)       x_inet_ntoa(in)
#define inet_addr(str)      x_inet_addr(str)
#define x_inet_pton(family, strptr, addrptr)    x_inet_pton (family, strptr, addrptr)
#define inet_ntop (family, addrptr, strptr, len)    x_inet_ntop (family, addrptr, strptr, len) 

#define sockaddr        x_sockaddr
#define sockaddr_in     x_sockaddr_in
#define timeval         x_timeval
#define close           x_close

#define socket(family, type, protocol)      x_socket(family, type, protocol)
#define sendto(s, buf, len, flags, dest, dlen)   x_sendto(s, buf, len, flags, dest, dlen)
#define recvfrom(s, buf, len, flags, src, slen)   x_recvfrom(s, buf, len, flags, src, slen)
#define setsockopt(s, level, optname, optval, len)   x_setsockopt(s, level, optname, optval, len)
#define connect(s, dest, dlen)    x_connect(s, dest, dlen)
#define send(s, buf, len, flags)   x_send(s, buf, len, flags)
#define recv(s, buf, len, flags)   x_recv(s, buf, len, flags)
#define bind(s, src, len)         x_bind(s, src, len)
#endif // !