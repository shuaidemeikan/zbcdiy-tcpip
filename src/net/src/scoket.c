#include "socket.h"
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
    req.sockfd = -1;
    req.create.family = family;
    req.create.protocol = protocol;
    req.create.type = type;

    net_err_t err = exmsg_func_exec(socket_create_req_in, &req);
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
        req.sockfd = s;
        req.data.buf = start;
        req.data.len = len;
        req.data.flags = 0;
        req.data.addr = (struct x_sockaddr *)dest;
        req.data.addrlen = dest_len;

        net_err_t err = exmsg_func_exec(socket_sendto_req_in, &req);
        if (err < 0)
        {
            dbg_ERROR(DBG_SOCKET, "create socket failed.");
            return -1;
        }

        len -= req.data.comp_len;
        send_size += req.data.comp_len;
        start += req.data.comp_len;
    }
    return send_size;
}