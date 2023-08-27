#include "sock.h"
#include "sys.h"
#include "exmsg.h"
#include "debug.h"
#include "socket.h"
#include "raw.h"

#define SOCKET_MAX_NR   10
static x_socket_t socket_tbl[SOCKET_MAX_NR];


static int get_index (x_socket_t* socket)
{
    return (int)(socket - socket_tbl);
}

static x_socket_t* get_socket (int index)
{
    if ((index < 0) || (index >= SOCKET_MAX_NR))
    {
        return (x_socket_t*)0;
    }
    return socket_tbl + index;
}

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

static void socket_free (x_socket_t* s)
{
    s->state = SOCKET_STATE_FREE;
}

net_err_t socket_init (void)
{
    plat_memset(socket_tbl, 0, sizeof(socket_tbl));
    return NET_ERR_OK;
}

net_err_t socket_create_req_in (struct _func_msg_t* msg)
{
    static const struct sock_info_t
    {
        int protocol;
        sock_t* (*create) (int family, int protocol);
    }sock_tbl[] = {
        [SOCK_RAW] = {.protocol = IPPROTP_ICMP, .create = raw_create,}
    };

    sock_req_t* req = (sock_req_t*)msg->param;
    socket_create_t* param = &req->create;

    x_socket_t* s = socket_alloc();
    if (!s)
    {
        dbg_ERROR(DBG_SOCKET, "no socket");
        return NET_ERR_MEM;
    }

    if ((param->type < 0) || (param->type >= sizeof(socket_tbl) / sizeof(socket_tbl[0])))
    {
        dbg_ERROR(DBG_SOCKET, "create sock failed");
        socket_free(s);
        return NET_ERR_PARAM;
    }

    const struct sock_info_t* info = socket_tbl + param->type;
    sock_t* sock = info->create;

    req->sockfd = get_index(s);
    return NET_ERR_OK;
}

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

net_err_t socket_sendto_req_in (struct _func_msg_t* msg)
{
    return NET_ERR_OK;
}