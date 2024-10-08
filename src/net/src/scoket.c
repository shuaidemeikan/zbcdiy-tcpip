﻿#include "socket.h"
#include "debug.h"
#include "exmsg.h"
#include "sock.h"

/**
 * 获得一个socket结构
 * @param family 套接字结构的协议簇类型
 * @param type 套接字本身的类型
 * @param protocol 上层协议类型
 * @return 获得到的socket结构编号
 */
int x_socket(int family, int type, int protocol)
{
    sock_req_t req;
    req.wait = (sock_wait_t*)0;
    req.wait_tmo = 0;
    req.sockfd = -1;
    req.create.family = family;
    req.create.protocol = protocol;
    req.create.type = type;

    net_err_t err = exmsg_func_exec(sock_create_req_in, &req);
    if (err < 0)
    {
        dbg_ERROR(DBG_SOCKET, "create socket failed.");
        return -1;
    }

    return req.sockfd;
}

/**
 * 把数据包发送出去
 * @param s 套接字
 * @param buf 数据包本体
 * @param flags 不知道是什么
 * @param dest 目标地址
 * @param dest_len 目标地址长度
 * @return 发送成功的大小
 */
ssize_t x_sendto(int s, const void* buf, size_t len, int flags, const struct x_sockaddr* dest, x_socklen_t dest_len)
{
    if (!buf || !len)
    {
        dbg_error(DBG_SOCKET, "sendto failed, buf or len is null.");
        return -1;
    }

    if ((dest->sin_family != AF_INET)|| (dest_len != sizeof(struct x_sockaddr_in)))
    {
        dbg_error(DBG_SOCKET, "sendto failed, dest or dest_len is error.");
        return -1;
    }
    ssize_t send_size = 0;                  // 用来统计总共发送了多少
    uint8_t* start = (uint8_t*)buf;         // 发送的地址
    while (len > 0)
    {
        sock_req_t req;
        req.wait = (sock_wait_t*)0;
        req.wait_tmo = 0;
        req.sockfd = s;
        req.data.buf = start;
        req.data.len = len;
        req.data.flags = 0;
        req.data.addr = (struct x_sockaddr *)dest;
        req.data.addrlen = &dest_len;

        net_err_t err = exmsg_func_exec(sock_sendto_req_in, &req);
        if (err < 0)
        {
            dbg_ERROR(DBG_SOCKET, "create socket failed.");
            return -1;
        }

        if (req.wait && ((err = sock_wait_enter(req.wait, req.wait_tmo)) < 0))
        {
            dbg_error(DBG_SOCKET, "recv failed");
            return -1;
        }

        len -= req.data.comp_len;
        send_size += req.data.comp_len;
        start += req.data.comp_len;
    }
    return send_size;
}

ssize_t x_recvfrom(int s, void* buf, size_t len, int flags, const struct x_sockaddr* src, x_socklen_t* src_len)
{
    if (!buf || !len || !src)
    {
        dbg_error(DBG_SOCKET, "sendto failed, buf or len or src is null.");
        return -1;
    }
    while(1)
    {
        sock_req_t req;
        req.wait = (sock_wait_t*)0;
        req.wait_tmo = 0;
        req.sockfd = s;
        req.data.buf = buf;
        req.data.len = len;
        req.data.flags = 0;
        req.data.addr = (struct x_sockaddr *)src;
        req.data.addrlen = src_len;
        req.data.comp_len = 0;

        net_err_t err = exmsg_func_exec(sock_recvfrom_req_in, &req);
        // 函数到这里返回了，但是函数返回不代表读到了数据，可能目标主机还没来得及回应或者回应的数据包还在网络上
        // 当下层的函数没有读到数据时，会在req内封装一个信号量返回回来，sock_wait_enter是一个封装了等待信号量的函数
        // 而这个信号量会在协议栈内部收到目标主机发过来的包时增加
        // 所以当第一次while没有读到数据时，应用程序就会在这卡住，等待协议栈内部收到了对应socket的回包时，才会继续运行
        if (err < 0)
        {
            dbg_ERROR(DBG_SOCKET, "create socket failed.");
            return -1;
        }

        if (req.data.comp_len)
            return (ssize_t)req.data.comp_len;

        err = sock_wait_enter(req.wait, req.wait_tmo);
        if (err == NET_ERR_CLOSE)
        {
            dbg_info(DBG_SOCKET, "remote close");
            return 0;
        }
        
        if (err < 0)
        {
            dbg_error(DBG_SOCKET, "recv failed");
            return -1;
        }
    }
}

int x_setsockopt(int s, int level, int optname, const char* optval, int len)
{
    if (!optval || !len)
    {
        dbg_error(DBG_SOCKET, "setsockopt failed, optval or len is null.");
        return -1;
    }

    sock_req_t req;
    req.wait = (sock_wait_t*)0;
    req.wait_tmo = 0;
    req.sockfd = -1;
    req.opt.level = level; 
    req.opt.optname = optname;
    req.opt.optval = optval;
    req.opt.len = len;

    net_err_t err = exmsg_func_exec(sock_setsockopt_req_in, &req);
    if (err < 0)
    {
        dbg_ERROR(DBG_SOCKET, "create socket failed.");
        return -1;
    }

    return 0;
}

int x_close (int s)
{
    sock_req_t req;
    req.wait = (sock_wait_t*)0;
    req.wait_tmo = 0;
    req.sockfd = s;

    net_err_t err = exmsg_func_exec(sock_close_req_in, &req);
    if (err < 0)
    {
        dbg_ERROR(DBG_SOCKET, "create socket failed.");
        return -1;
    }

    return 0;
}

int x_connect(int sockfd, const struct x_sockaddr* addr, x_socklen_t len)
{
    if (len != sizeof(struct x_sockaddr) || !addr)
    {
        dbg_error(DBG_SOCKET, "socket connect addr error");
        return -1;
    }

    if (addr->sin_family != AF_INET)
    {
        dbg_error(DBG_SOCKET, "socket connect addr family error");
        return -1;
    }

    const struct x_sockaddr_in* addr_in = (const struct x_sockaddr_in*)addr;
    if ((addr_in->sin_addr.s_addr == INADDR_ANY) && !addr_in->sin_port)
    {
        dbg_error(DBG_SOCKET, "ip or port is empty");
        return -1;
    }

    sock_req_t req;
    req.wait = (sock_wait_t*)0;
    req.sockfd = sockfd;
    req.conn.addr = addr;
    req.conn.addrlen = len;

    net_err_t err = exmsg_func_exec(sock_connect_req_in, &req);
    if (err < 0)
    {
        dbg_ERROR(DBG_SOCKET, "socket connect do fun failed.");
        return -1;
    }

    if (req.wait && ((err = sock_wait_enter(req.wait, req.wait_tmo)) < 0))
    {
        dbg_error(DBG_SOCKET, "recv failed");
        return -1;
    }

    return 0;
}

ssize_t x_send(int s, const void* buf, size_t len, int flags)
{
     if (!buf || !len)
    {
        dbg_error(DBG_SOCKET, "sendto failed, buf or len is null.");
        return -1;
    }

    ssize_t send_size = 0;                  // 用来统计总共发送了多少
    uint8_t* start = (uint8_t*)buf;         // 发送的地址
    while (len > 0)
    {
        sock_req_t req;
        req.wait = (sock_wait_t*)0;
        req.wait_tmo = 0;
        req.sockfd = s;
        req.data.buf = start;
        req.data.len = len;
        req.data.flags = 0;

        net_err_t err = exmsg_func_exec(sock_send_req_in, &req);
        if (err < 0)
        {
            dbg_ERROR(DBG_SOCKET, "create socket failed.");
            return -1;
        }

        if (req.wait && ((err = sock_wait_enter(req.wait, req.wait_tmo)) < 0))
        {
            dbg_error(DBG_SOCKET, "recv failed");
            return -1;
        }

        len -= req.data.comp_len;
        send_size += req.data.comp_len;
        start += req.data.comp_len;
    }
    return send_size;
}

ssize_t x_recv(int s, void* buf, size_t len, int flags)
{
    if (!buf || !len)
    {
        dbg_error(DBG_SOCKET, "sendto failed, buf or len or src is null.");
        return -1;
    }
    while(1)
    {
        sock_req_t req;
        req.wait = (sock_wait_t*)0;
        req.wait_tmo = 0;
        req.sockfd = s;
        req.data.buf = buf;
        req.data.len = len;
        req.data.flags = 0;
        req.data.comp_len = 0;

        net_err_t err = exmsg_func_exec(sock_recv_req_in, &req);
        if (err < 0)
        {
            dbg_ERROR(DBG_SOCKET, "create socket failed.");
            return -1;
        }

        if (req.data.comp_len)
            return (ssize_t)req.data.comp_len;

        err = sock_wait_enter(req.wait, req.wait_tmo);
        if (err == NET_ERR_CLOSE)
        {
            dbg_info(DBG_SOCKET, "remote close");
            return 0;
        }
        if (err < 0)
        {
            dbg_error(DBG_SOCKET, "recv failed");
            return -1;
        }
    }
}

int x_bind(int s, const struct x_sockaddr* src, x_socklen_t len)
{
    if (len != sizeof(struct x_sockaddr) || !src)
    {
        dbg_error(DBG_SOCKET, "socket connect addr error");
        return -1;
    }

    if (src->sin_family != AF_INET)
    {
        dbg_error(DBG_SOCKET, "socket connect addr family error");
        return -1;
    }

    const struct x_sockaddr_in* addr_in = (const struct x_sockaddr_in*)src;
    if ((addr_in->sin_addr.s_addr == INADDR_ANY) || !addr_in->sin_port)
    {
        dbg_error(DBG_SOCKET, "ip or port is empty");
        return -1;
    }

    sock_req_t req;
    req.wait = (sock_wait_t*)0;
    req.sockfd = s;
    req.conn.addr = src;
    req.conn.addrlen = len;

    return exmsg_func_exec(sock_bind_req_in, &req);
}