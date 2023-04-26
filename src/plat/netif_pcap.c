#include "netif_pcap.h"
#include "sys_plat.h"
#include "exmsg.h"
#include "pcap.h"
#include "net_err.h"
#include "debug.h"

#define ETHER_MTU  1500

void recv_thread(void* arg)
{
    plat_printf("recv thread is running...\n");

    while(1)
    {
        sys_sleep(1);
        exmsg_netif_in((netif_t *)0);
    }  
}

void xmit_thread(void* arg)
{
    plat_printf("xmit thread is running...\n");

    while(1)
        sys_sleep(1);
}

static net_err_t netif_pcap_open(struct _netif_t* netif, void* data)
{
    // 先将封装好的数据转成我们定义的pcap_data_t格式，内部包含了ip和mac地址
    pcap_data_t* dev_data = (pcap_data_t*)data;

    // 用dev_data的数据调用pcap的接口，打开一个网卡
    pcap_t* pcap = pcap_device_open(dev_data->ip, dev_data->hwaddr);
    if (pcap == (pcap_t*)0)
    {
        dbg_ERROR(DBG_NETIF, "pcap open failed! name: %s\n", netif->name);
        return NET_ERR_IO;
    }

    // 网卡打开了，初始化一些网卡结构内的数据
    netif->type = NETIF_TYPE_ETHER;
    netif->mtu = ETHER_MTU;
    netif->ops_data = pcap;
    // 正常mac地址的长度为6个字节
    netif_set_hwaddr(netif, dev_data->hwaddr, 6);

    sys_thread_create(recv_thread, netif);
    sys_thread_create(xmit_thread, netif);
    return NET_ERR_OK;
}

static void netif_pcap_close(struct _netif_t* netif)
{
    pcap_t* pcap = (pcap_t*)netif->ops_data;
    pcap_close(pcap);
}

static net_err_t netif_pcap_xmit(struct _netif_t* netif)
{
    return NET_ERR_OK;
}

const netif_ops_t netdev_ops = {
    .open = netif_pcap_open,
    .close = netif_pcap_close,
    .xmit = netif_pcap_xmit,
};