#include "net.h"
#include "exmsg.h"
#include "net_plat.h"
#include "net_err.h"
#include "pktbuf.h"
#include "debug.h"
#include "netif.h"
#include "loop.h"
#include "timer.h"
#include "ether.h"
#include "arp.h"
#include "ipv4.h"
#include "sock.h"
#include "raw.h"
#include "udp.h"

net_err_t net_init(void)
{
    dbg_info(DBG_INIT, "init net");
    rt_init();
    netif_init();
    net_plat_init();
    exmsg_init();
    net_err_t err = pktbuf_init();
    net_timer_init();
    loop_init();
    ether_init();
    arp_init();
    ipv4_init();
    socket_init();
    raw_init();
    udp_init();
    return NET_ERR_OK;
}
net_err_t net_start(void)
{
    exmsg_start();
    dbg_info(DBG_INIT, "net is running");
    return NET_ERR_OK;
}