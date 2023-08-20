#include "socket.h"
#include "debug.h"
#include "exmsg.h"
#include "sock.h"

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