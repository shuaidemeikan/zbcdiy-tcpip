﻿#include "netif.h"
#include "mblock.h"
#include "debug.h"
#include "sys.h"
#include "exmsg.h"
#include "ether.h"
#include "protocol.h"
#include "ipv4.h"

// 存储网卡结构体实际的内存
static netif_t netif_buffer[NETIF_DEV_CNT];
// 用以便捷的分配网卡结构体
static mblock_t netif_mblock;
// 用以把分配出来的网卡结构体串起来
static nlist_t netif_list;
// 默认网卡
static netif_t* netif_default;

static const link_layer_t* link_layers[NETIF_TYPE_SIZE];

#if DBG_DISP_ENABLED(DBG_NETIF)
void display_netif_list(void)
{
    plat_printf("netif list:\n");

    nlist_node_t* node;
    nlist_for_each(node, &netif_list)
    {
        netif_t* netif = nlist_entry(node, netif_t, node);
        plat_printf("%s:", netif->name);
        switch (netif->state)
        {
        case NETIF_CLOSED:
            plat_printf("  %s  ", "closed");
            break;
        
        case NETIF_OPENED:
            plat_printf("  %s  ", "opened");
            break;

        case NETIF_ACTIVE:
            plat_printf("  %s  ", "active");
            break;
        default:
            break;
        }

        switch (netif->type)
        {
        case NETIF_TYPE_ETHER:
            plat_printf("  %s  ", "ether");
            break;
        
        case NETIF_TYPE_LOOP:
            plat_printf("  %s  ", "loop");
            break;
        default:
            break;
        }

        plat_printf(" mtu=%d \n", netif->mtu);
        dbg_dump_hwaddr("hwaddr: ", netif->hwadder.addr, netif->hwadder.len);
        dbg_dump_ip(" ip:", &netif->ipaddr);
        dbg_dump_ip(" netmask:", &netif->netmask);
        dbg_dump_ip(" geteway:", &netif->gateway);
        plat_printf("\n");
        

    }
}

#else
#define display_netif_list()
#endif

/**
 * netif模块整体的初始化
 * 主要在于初始化一个用于分配网卡的mblock，同时初始化一下默认的网卡设备
 * @return err类型的返回值
 */
net_err_t netif_init(void)
{
    dbg_info(DBG_NETIF, "init netif");
    nlist_init(&netif_list);
    mblock_init(&netif_mblock, &netif_buffer, sizeof(netif_t), NETIF_DEV_CNT, NLOCKER_NONE);

    netif_default = (netif_t*)0;
    plat_memset((void*)link_layers, 0, sizeof(link_layers));
    dbg_info(DBG_NETIF, "netif init done");
    return NET_ERR_OK;
}

net_err_t netif_register_layer(int type, const link_layer_t* layer)
{
    if ((type <0) || (type >= NETIF_TYPE_SIZE))
    {
        dbg_ERROR(DBG_NETIF, "type error");
        return NET_ERR_PARAM;
    }

    if (link_layers[type])
    {
        dbg_ERROR(DBG_NETIF, "link layer exist");
        return NET_ERR_EXIST;
    }

    link_layers[type] = layer;
    return NET_ERR_OK;
}

/**
 * 获得对应类型的数据链路层处理函数
 * @param type 对应的数据链路层类型
 * @return 对应数据链路层类型的处理函数
 */
static const link_layer_t* netif_get_layer(int type)
{
    if ((type < 0) || (type >= NETIF_TYPE_SIZE))
    {
        dbg_ERROR(DBG_NETIF, "type error");
        return (const link_layer_t*)0;
    }

    return link_layers[type];
}

/**
 * 从mblock里获得一个网卡结构，用于后续操作
 * 注意这里仅仅只是获得一个网卡结构并且简单的初始化了一下，实际上对网卡真正有用的数据一个也没写
 * 具体初始化了以下的数据
 * ipaddr, netmask, gateway, name , hwaddr, type, mtu, node(node是真的被插入到了全部网卡的链表里), fixq, state, ops, ops_data
 * @param dev_name 要打开的网卡名
 * @return err类型的返回值
 */
netif_t* netif_open(const char* dev_name, const netif_ops_t* ops, void* ops_data)
{
    // 从mblock里分配一个netif
    netif_t* netif = mblock_alloc(&netif_mblock, -1);
    if (!netif)
    {
        dbg_ERROR(DBG_NETIF, "no netif.");
        return (netif_t*)0;
    }

    // 对neiif内的参数初始化
    ipaddr_set_any(&netif->ipaddr);
    ipaddr_set_any(&netif->netmask);
    ipaddr_set_any(&netif->gateway);

    plat_strncpy(netif->name, dev_name, NETIF_NAME_SIZE);
    netif->name[NETIF_NAME_SIZE - 1] = '\0';

    plat_memset(&netif->hwadder, 0, sizeof(netif_hwaddr_t));
    netif->type = NETIF_TYPE_NONE;
    netif->mtu = 0;
    nlist_node_init(&netif->node);

    net_err_t err = fixq_init(&netif->in_q, netif->in_q_buf, NETIF_INQ_SIZE, NLOCKER_THREAD);
    if (err < 0)
    {
        dbg_ERROR(DBG_NETIF, "netif in_q init failed.");
        mblock_free(&netif_mblock, netif);
        return (netif_t*)0;
    }
    err = fixq_init(&netif->out_q, netif->out_q_buf, NETIF_INQ_SIZE, NLOCKER_THREAD);
    if (err < 0)
    {
        dbg_ERROR(DBG_NETIF, "netif out_q init failed.");
        // inq先创建，所以如果走到这，说明inq已经被初始化好了，这里得销毁
        fixq_destory(&netif->in_q);
        mblock_free(&netif_mblock, netif);
        return (netif_t*)0;
    }

    netif->ops = ops;
    netif->ops_data = ops_data;
    err = ops->open(netif, ops_data);
    if (err < 0)
    {
        dbg_ERROR(DBG_NETIF, "netif ops open err");
        goto free_return;
    }
    
    netif->state = NETIF_OPENED;

    // 意义不明的判断，进行到这里理应不会有任何代码修改type的
    if (netif->type == NETIF_TYPE_NONE)
    {
        dbg_ERROR(DBG_NETIF, "netif type unknow");
        goto free_return;
    }

    // 初始化netif_layer_t
    netif->link_layer = netif_get_layer(netif->type);
    if((netif->link_layer == (const link_layer_t*)0) && (netif->type != NETIF_TYPE_LOOP))
    {
        dbg_ERROR(DBG_NETIF, "no link layer,netif name: %s\n", dev_name);
        goto free_return;
    }

    // 把当前网卡插入到总网卡链表的最后一个节点，方便操作
    nlist_insert_last(&netif_list, &netif->node);
    display_netif_list();
    return netif;

free_return:
    if (netif->state == NETIF_OPENED)
        netif->ops->close(netif);
    fixq_destory(&netif->in_q);
    fixq_destory(&netif->out_q);
    mblock_free(&netif_mblock, netif);
    return (netif_t*)0;


}

/**
 * 设置一个网卡结构内和ip有关的数据
 * @param netif 被操作的网卡结构
 * @param ip 设置网卡结构内的ip
 * @param netmask 设置网卡结构内的掩码
 * @param gateway 设置网卡结构内的网关
 * @return err类型的返回值
 */
net_err_t netif_set_addr (netif_t* netif, ipaddr_t* ip, ipaddr_t* netmask, ipaddr_t* gateway)
{
    ipaddr_copy(&netif->ipaddr, ip ? ip : ipaddr_get_any());
    ipaddr_copy(&netif->netmask, netmask ? netmask : ipaddr_get_any());
    ipaddr_copy(&netif->gateway, gateway ? gateway : ipaddr_get_any());
    return NET_ERR_OK;
}

/**
 * 设置一个网卡结构内的硬件地址
 * @param netif 被操作的网卡结构
 * @param hwaddr 存储硬件地址的字符串
 * @param len 硬件地址的长度
 * @return err类型的返回值
 */
net_err_t netif_set_hwaddr(netif_t* netif, const char* hwaddr, int len)
{
    plat_memcpy(&netif->hwadder, hwaddr, len);
    netif->hwadder.len = len;
    return NET_ERR_OK;
}

/**
 * 激活一个网卡
 * @param netif 被激活的网卡
 * @return err类型的返回值
 */
net_err_t netif_set_active (netif_t * netif)
{
    // 网卡只有处于被打开的状态下才能被激活
    if (netif->state != NETIF_OPENED)
    {
        dbg_ERROR(DBG_NETIF, "netif is not opened");
        return NET_ERR_STATE;
    }    

    if (netif->link_layer)
    {
        net_err_t err = netif->link_layer->open(netif);
        if (err < 0)
        {
            dbg_info(DBG_NETIF, "active error");
            return err;
        }
    }

    if (!netif_default && netif->type != NETIF_TYPE_LOOP)
        netif_set_default(netif);

    // 添加对应网卡的路由
    ipaddr_t ip;
    uint32_t ip_buf = get_network(&netif->ipaddr, &netif->netmask);
    ipaddr_from_buf(&ip, (uint8_t*)(&ip_buf));
    //rt_add(&netif->ipaddr, &netif->netmask, ipaddr_get_any(), netif);
    rt_add(&ip, &netif->netmask, ipaddr_get_any(), netif);
    ipaddr_from_str(&ip, bro_addr);
    rt_add(&netif->ipaddr, &ip, ipaddr_get_any(), netif);
    netif->state = NETIF_ACTIVE;
    display_netif_list();
    return NET_ERR_OK;
}

/**
 * 关闭激活一个网卡（关闭激活是一个很奇怪的词，意思就是激活的反义词）
 * @param netif 被关闭激活的网卡
 * @return err类型的返回值
 */
net_err_t netif_set_deactive (netif_t * netif)
{
    // 网卡只有处于被激活状态才能关闭激活
    if (netif->state != NETIF_ACTIVE)
    {
        dbg_ERROR(DBG_NETIF, "netif is not actived");
        return NET_ERR_STATE;
    }   

    if (netif->link_layer)
        netif->link_layer->close(netif);

    // 释放两个fixq内的数据
    pktbuf_t* buf;
    while((buf = fixq_recv(&netif->in_q, -1)) != (pktbuf_t*)0)
        pktbuf_free(buf);
    while((buf = fixq_recv(&netif->out_q, -1)) != (pktbuf_t*)0)
        pktbuf_free(buf);

    // 设置默认网卡
    if (netif_default == netif)
    {
        netif_default = (netif_t*)0;
        rt_remove(ipaddr_get_any(), ipaddr_get_any());
    }
        

    ipaddr_t ip;
    uint32_t ip_buf = get_network(&netif->ipaddr, &netif->netmask);
    ipaddr_from_buf(&ip, (uint8_t*)(&ip_buf));
    //rt_add(&netif->ipaddr, &netif->netmask, ipaddr_get_any(), netif);
    rt_remove(&ip, &netif->netmask);
    ipaddr_from_str(&ip, bro_addr);
    rt_remove(&netif->ipaddr, &ip);

    netif->state = NETIF_OPENED;
    display_netif_list();
    return NET_ERR_OK;
    
}

/**
 * 关闭一个网卡，销毁网卡内部的nlist，fixq，并且将网卡结构释放掉
 * @param netif 被关闭激活的网卡
 * @return err类型的返回值
 */
net_err_t netif_close (netif_t* netif)
{
    // 网卡只有处于close状态才能被关闭
    if (netif->state == NETIF_ACTIVE)
    {
        dbg_ERROR(DBG_NETIF, "netif is activing, you must close it first.");
        return NET_ERR_STATE;
    }

    netif->ops->close(netif);
    nlist_remove(&netif_list, &netif->node);
    fixq_destory(&netif->in_q);
    fixq_destory(&netif->out_q);
    mblock_free(&netif_mblock, netif);
    display_netif_list();
    return NET_ERR_OK;
}

void netif_set_default (netif_t* netif)
{
    netif_default = netif;
    if (!(ipaddr_is_any(&netif->gateway)))
    {
        if (netif_default)
            rt_remove(ipaddr_get_any(), ipaddr_get_any());
        rt_add(ipaddr_get_any(), ipaddr_get_any(), &netif->gateway, netif_default);
    }
}

// 以下四个函数都是往网卡内部的消息队列写数据

/**
 * 往对应网卡的输入队列里写一个包
 * 用于pcap接口收到网卡的数据之后立刻将该数据写入网卡的in_q队列
 * 写入后调用exmsg_netif_in用来通知全局有包进入协议栈了
 * @param netif 往那张网卡写
 * @param buf 写的具体内容
 * @param tmo 等待的时间
 * @return err类型的返回值
 */
net_err_t netif_put_in (netif_t* netif, pktbuf_t* buf, int tmo)
{
    net_err_t err = fixq_send(&netif->in_q, buf, tmo);
    if (err < 0)
    {
        dbg_info(DBG_NETIF, "netif in_q full");
        return NET_ERR_FULL;
    }

    exmsg_netif_in(netif);
    return NET_ERR_OK;
}

/**
 * 从对应网卡的输入队列里取一个包出来，如果消息队列里没有包，就会卡在第一条语句这里
 * 通常来说，别的线程调用上面的函数往这张网卡的输出队列里写一个包
 * 然后就由对应网卡的xmit线程调用这个函数读出来一个包，最后直接发送，也就是说这个函数通常是发送的倒数第二步
 * @param netif 从哪张网卡取
 * @param tmo 取的等待时间，一般都不等待
 * @return 取出来的包
 */
pktbuf_t* netif_get_in (netif_t* netif, int tmo)
{
    pktbuf_t* buf =fixq_recv(&netif->in_q, tmo);
    if (!buf)
    {
        dbg_info(DBG_NETIF, "netif in_q empty");
        return (pktbuf_t*)0;
    }

    pktbuf_reset_acc(buf);
    return buf;
}

/**
 * 往对应网卡的输出队列里写一个包
 * 别的线程调用这个函数往网卡内写一个包，然后对应网卡的xmit线程调用下面的函数发出去
 * 也就是说，这个函数通常是发送的倒数第三步
 * @param netif 往那张网卡写
 * @param buf 写的具体内容
 * @param tmo 等待的时间
 * @return err类型的返回值
 */
net_err_t netif_put_out (netif_t* netif, pktbuf_t* buf, int tmo)
{
    net_err_t err = fixq_send(&netif->out_q, buf, tmo);
    if (err < 0)
    {
        dbg_info(DBG_NETIF, "netif out_q full");
        return NET_ERR_FULL;
    }

    return NET_ERR_OK;
}

/**
 * 从对应网卡的输出队列里取一个包出来，如果消息队列里没有包，就会卡在第一条语句这里
 * 通常来说，别的线程调用上面的函数往这张网卡的输出队列里写一个包
 * 然后就由对应网卡的xmit线程调用这个函数读出来一个包，最后直接发送，也就是说这个函数通常是发送的倒数第二步
 * @param netif 从哪张网卡取
 * @param tmo 取的等待时间，一般都不等待
 * @return 取出来的包
 */
pktbuf_t* netif_get_out (netif_t* netif, int tmo)
{
    pktbuf_t* buf = fixq_recv(&netif->out_q, tmo);
    if (!buf)
    {
        dbg_info(DBG_NETIF, "netif out_q empty");
        return (pktbuf_t*)0;
    }

    pktbuf_reset_acc(buf);
    return buf;
}

/**
 * 从网卡往外发送一个数据包，具体怎么发送，由网卡内部ops的xmit函数决定
 * @param netif 从哪张网卡发送
 * @param ipaddr 目标地址
 * @param buf 发送的数据包
 * @return err类型的返回值
 */
net_err_t netif_out(netif_t* netif, ipaddr_t* ipaddr, pktbuf_t* buf)
{
    // 协议栈本质上只支持以太网和环回网卡，所以可以用netif中是否初始化过link_layer来判断是不是以太网
    // 如果是以太网，调用一下以太网的处理方式来发送这个包
    if (netif->link_layer)
    {
        //net_err_t err = ether_raw_out(netif, NET_PROTOCOL_ARP, ether_broadcast_addr(), buf);
        net_err_t err = netif->link_layer->out(netif, ipaddr, buf);
        if (err < 0)
        {
            dbg_WARNING(DBG_NETIF, "netif link out err");
            return err;
        }
        return NET_ERR_OK;
    }else
    {
        net_err_t err = netif_put_out(netif, buf, -1);
        if (err < 0)
        {
            dbg_info(DBG_NETIF, "send failed, queue full");
            return err;
        }

        pktbuf_inc_ref(buf);

        return netif->ops->xmit(netif);
    }  
}

netif_t* netif_get_default (void)
{
    return netif_default;
}