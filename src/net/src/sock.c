#include "sock.h"
#include "sys.h"
#include "exmsg.h"
#include "debug.h"
#include "socket.h"
#include "raw.h"

#define SOCKET_MAX_NR   10
static x_socket_t socket_tbl[SOCKET_MAX_NR];

/**
 * 从一个socket结构拿到该socket的编号
 * @param socket socket结构
 * @return 该socket的编号
 */
static int get_index (x_socket_t* socket)
{
    return (int)(socket - socket_tbl);
}

/**
 * 从一个编号拿到一个socket结构
 * @param index 编号
 * @return 编号对应的socket
 */
static x_socket_t* get_socket (int index)
{
    if ((index < 0) || (index >= SOCKET_MAX_NR))
    {
        return (x_socket_t*)0;
    }
    return socket_tbl + index;
}

/**
 * 从socket池内拿到一个socket
 * @return 拿到的socket结构，如果socket池内没有空闲的结构，就会返回0
 */
static x_socket_t* socket_alloc (void)
{
    x_socket_t* s = (x_socket_t*)0;
    for (int i = 0; i < SOCKET_MAX_NR; i++)
    {
        x_socket_t* socket = socket_tbl + i;
        if (socket->state == SOCKET_STATE_FREE)
        {
            socket->state = SOCKET_STATE_USED;
            s = socket;
            break;
        }
    }
    return s;
}

/**
 * 释放一个socket结构
 * @param s 待释放的socket
 */
static void socket_free (x_socket_t* s)
{
    s->state = SOCKET_STATE_FREE;
}

/**
 * 初始化socket模块
 * @return 初始化是否成功
 */
net_err_t socket_init (void)
{
    plat_memset(socket_tbl, 0, sizeof(socket_tbl));
    return NET_ERR_OK;
}

/**
 * 创建一个socket结构，该函数由socket.c文件通知工作线程调用
 * @param msg 
 * @return 创建是否成功
 */
net_err_t socket_create_req_in (struct _func_msg_t* msg)
{
    // 这里定义了一个提供创建不同类型socket的不同方法的数组
    static const struct sock_info_t
    {
        int protocol;
        sock_t* (*create) (int family, int protocol);
    }sock_tbl[] = {
        [SOCK_RAW] = {.protocol = IPPROTP_ICMP, .create = raw_create,}
    };

    // 解析一下参数
    sock_req_t* req = (sock_req_t*)msg->param;
    socket_create_t* param = &req->create;

    // 获得一个socket
    x_socket_t* s = socket_alloc();
    if (!s)
    {
        dbg_ERROR(DBG_SOCKET, "no socket");
        return NET_ERR_MEM;
    }

    // 检查参数有效性
    if ((param->type < 0) || (param->type >= sizeof(socket_tbl) / sizeof(socket_tbl[0])))
    {
        dbg_ERROR(DBG_SOCKET, "create sock failed");
        socket_free(s);
        return NET_ERR_PARAM;
    }

    // 从上面定义的数组里取出来对应的当前要创建的socket类型的创建函数
    const struct sock_info_t* info = sock_tbl + param->type;
    if (param->protocol == 0)
        param->protocol = info->protocol;

    sock_t* sock = info->create(param->family, param->protocol);
    if (!sock)
    {
        dbg_error(DBG_SOCKET, "create sock failed");
        socket_free(s);
        return NET_ERR_MEM;
    }

    s->sock = sock;
    req->sockfd = get_index(s);
    return NET_ERR_OK;
}

// 初始化一个sock(注意，不是socket)
net_err_t sock_init(sock_t* sock, int family, int protocol, const sock_opt_t* ops)
{
    sock->protocol = protocol;
    sock->family = family;
    sock->ops = ops;
    ipaddr_set_any(&sock->local_ip);
    ipaddr_set_any(&sock->remote_ip);
    sock->local_port = 0;
    sock->remote_port = 0;
    sock->err = NET_ERR_OK;
    sock->recv_tmo = 0;
    sock->send_tmo = 0;
    nlist_node_init(&sock->node);
    return NET_ERR_OK;
}

/**
 * 工作线程实际上调用的socket接口的发送函数
 * @param msg 发送函数需要的参数
 * @return err类型的返回值
 */
net_err_t socket_sendto_req_in (struct _func_msg_t* msg)
{
    // 取出参数
    sock_req_t* req = (sock_req_t*)msg->param;
    x_socket_t* s = get_socket(req->sockfd);
    if (!s)
    {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }
    sock_t* sock = s->sock;
    sock_data_t* data = &req->data;

    if (!sock->ops->sendto)
    {
        dbg_error(DBG_SOCKET, "funtion not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    // 调对应socket类型的发送函数
    net_err_t err = sock->ops->sendto(sock, data->buf, data->len, data->flags, data->addr, data->addrlen, &data->comp_len);
    return err;
}