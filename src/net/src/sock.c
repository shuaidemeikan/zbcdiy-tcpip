#include "sock.h"
#include "sys.h"
#include "exmsg.h"
#include "debug.h"
#include "socket.h"
#include "raw.h"

#define SOCKET_MAX_NR   10
static x_socket_t socket_tbl[SOCKET_MAX_NR];

net_err_t sock_wait_init (sock_wait_t* wait)
{
    wait->waitting = 0;
    wait->err = NET_ERR_OK;
    wait->sem = sys_sem_create(0);
    return wait->sem == SYS_SEM_INVALID ? NET_ERR_SYS : NET_ERR_OK;
}

void sock_wait_destory (sock_wait_t* wait)
{
    if (wait->sem != SYS_SEM_INVALID)
        sys_sem_free(wait->sem);
}
void sock_wait_add (sock_wait_t* wait, int tmo, struct _sock_req_t* req)
{
    wait->waitting++;
    req->wait = wait;
    req->wait_tmo = tmo;
}

net_err_t sock_wait_enter (sock_wait_t* wait, int tmo)
{
    // 等待tmo这么长时间，如果小于0，就说明等待超时了
    if (sys_sem_wait(wait->sem, tmo) < 0)
        return NET_ERR_TMO;

    return wait->err;
}

void sock_wait_leave (sock_wait_t* wait, net_err_t err)
{
    if (wait->waitting > 0)
    {
        wait->waitting--;
        sys_sem_notify(wait->sem);
        wait->err = err;
    }
}

void sock_wakeup (sock_t* sock, int type, int err)
{
    if (type & SOCK_WAIT_CONN)
        sock_wait_leave(sock->conn_wait, err);
    if (type & SOCK_WAIT_WRITE)
        sock_wait_leave(sock->send_wait, err);
    if (type & SOCK_WAIT_READ)
        sock_wait_leave(sock->recv_wait, err);
}

void sock_uninit(sock_t* sock)
{
    if(sock->recv_wait)
        sock_wait_destory(sock->recv_wait);
    if(sock->conn_wait)
        sock_wait_destory(sock->conn_wait);
    if(sock->send_wait)
        sock_wait_destory(sock->send_wait);
}

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

net_err_t sock_setopt (struct _sock_t* s, int level, int optname, const char* optval, int len)
{
    if (level != SOL_SOCKET)
    {
        dbg_ERROR(DBG_SOCKET, "unknown level");
        return NET_ERR_PARAM;
    }

    switch (optname)
    {
        case SO_RCVTIMEO:
        case SO_SNDTIMEO:
        {
            if (len != sizeof(struct x_timeval))
            {
                dbg_error(DBG_SOCKET, "time size error");
                return NET_ERR_PARAM;
            }

            struct x_timeval* tv = (struct x_timeval*)optval;
            int time_ms = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (optname == SO_RCVTIMEO)
            {
                s->recv_tmo = time_ms;
                return NET_ERR_OK;
            }else if (optname == SO_SNDTIMEO)
            {
                s->send_tmo = time_ms;
                return NET_ERR_OK;
            }else
                return NET_ERR_PARAM;
            break;
        }
        default:
            break;
    }

    return NET_ERR_PARAM;
}

/**
 * 创建一个socket结构，该函数由socket.c文件通知工作线程调用
 * @param msg 
 * @return 创建是否成功
 */
net_err_t sock_create_req_in (struct _func_msg_t* msg)
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
net_err_t sock_init(sock_t* sock, int family, int protocol, const sock_ops_t* ops)
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
    sock->recv_wait = (sock_wait_t*)0;
    sock->send_wait = (sock_wait_t*)0;
    sock->conn_wait = (sock_wait_t*)0;
    return NET_ERR_OK;
}

/**
 * 工作线程实际上调用的socket接口的发送函数
 * @param msg 发送函数需要的参数
 * @return err类型的返回值
 */
net_err_t sock_sendto_req_in (struct _func_msg_t* msg)
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
    net_err_t err = sock->ops->sendto(sock, data->buf, data->len, data->flags, data->addr, *data->addrlen, &data->comp_len);
    
    if (err == NET_ERR_NEED_WAIT)
    {
        if (sock->send_wait)
            sock_wait_add(sock->send_wait, sock->send_tmo, req);
    }
    
    return err;
}

net_err_t sock_recvfrom_req_in (struct _func_msg_t* msg)
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

    if (!sock->ops->recvfrom)
    {
        dbg_error(DBG_SOCKET, "funtion not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    // 调对应socket类型的发送函数
    net_err_t err = sock->ops->recvfrom(sock, data->buf, data->len, data->flags, data->addr, *data->addrlen, &data->comp_len);
    
    if (err == NET_ERR_NEED_WAIT)
    {
        if (sock->recv_wait)
            sock_wait_add(sock->recv_wait, sock->recv_tmo, req);
    }
    return err;
}

net_err_t sock_setsockopt_req_in (struct _func_msg_t* msg)
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
    sock_opt_t* opt = &req->opt;

    return sock->ops->setopt(sock, opt->level, opt->optname, opt->optval, opt->len);
    return NET_ERR_OK;
}

net_err_t sock_close_req_in (struct _func_msg_t* msg)
{
    sock_req_t* req = (sock_req_t*)msg->param;
    x_socket_t* s = get_socket(req->sockfd);

    if (!s)
    {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t* sock = s->sock;
    if (!sock->ops->close)
    {
        dbg_error(DBG_SOCKET, "funtion not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->close(sock);

    socket_free(s);
    return err;
}