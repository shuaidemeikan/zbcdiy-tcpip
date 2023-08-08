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

    // 把常用的数据先转好
    netif_t* netif = (netif_t*)arg;
    pcap_t* pcap = (pcap_t*)netif->ops_data;
    while(1)
    {
        // 下面的两个结构体是pcap库要求的，第一个是用来保存收到的包的信息，第二个是用来存储收到的包的具体内容
        struct pcap_pkthdr* pkthdr;
        const uint8_t* pkt_data;
        // 如果pcap接口读到的包有问题，那么就从新开始循环
        if (pcap_next_ex(pcap, &pkthdr, &pkt_data) != 1)
        {
            continue;
        }

        // 拿到一个pktbuf用来存储从网卡接收到的信息
        pktbuf_t* buf = pktbuf_alloc(pkthdr->len);
        if (buf == (pktbuf_t*)0)
        {
            dbg_WARNING(DBG_NETIF, "buf == NULL");
            continue;
        }

        pktbuf_write(buf, (uint8_t*)pkt_data, pkthdr->len);

        // 把pktbuf里的数据丢到消息队列里
        if (netif_put_in(netif, buf, 0) < 0)
        {
            dbg_WARNING(DBG_NETIF, "netif %s in_q full\n", netif->name);
            pktbuf_free(buf);
            continue;
        }
    }  
}

void xmit_thread(void* arg)
{
    plat_printf("xmit thread is running...\n");

    netif_t* netif = (netif_t*)arg;
    pcap_t* pcap = (pcap_t*)netif->ops_data;
    static uint8_t rw_buffer[1500+6+6+2];
    
    while(1)
    {
        // 从网卡的消息输出队列里取一个包，没有包就一直等
        pktbuf_t* buf = netif_get_out(netif, 0);
        if (buf == (pktbuf_t*)0)
            continue;
        
        // 走到这里就说明从网卡的输出消息队列里拿到了一个包
        int total_size = buf->total_size;
        plat_memset(rw_buffer, 0, sizeof(rw_buffer));
        pktbuf_read(buf, rw_buffer, total_size);
        pktbuf_free(buf);

        // 调pcap库的发送函数
        if (pcap_inject(pcap, rw_buffer, total_size) == -1)
        {
            plat_printf("pcap send faild:%s\n", pcap_geterr(pcap));
            plat_printf("pcap send faild, size:%d\n", total_size);
        }

    }
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