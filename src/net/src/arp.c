#include "arp.h"
#include "debug.h"
#include "mblock.h"
#include "pktbuf.h"
#include "tools.h"
#include "protocol.h"
#include "sys.h"

static arp_entry_t cache_tbl[ARP_CACHE_SIZE];       // arp可使用的系统中所有的内存
static mblock_t cache_mblock;                       // 用来分配上面的数据
static nlist_t cache_list;                           // arp链表

#if DBG_DISP_ENABLED(DBG_ETHER)

static void display_arp_entry (arp_entry_t* entry)
{
    plat_printf("%d: ", (int)(entry - cache_tbl));
    dbg_dump_ip_buf("  ip: ", entry->paddr);
    dbg_dump_hwaddr("  mac:", entry->hwaddr, ETHER_HWA_SIZE);

    plat_printf("tmo: %d, retry: %d, %s, buf: %d\n",
        entry->tmo, entry->retry, entry->state == NET_ARP_RESOLVED ? "stable" : "pending",
        nlist_count(&entry->buf_list));
}

static void display_arp_tbl(void)
{
    plat_printf("---------- arp table start ----------------\n");
    arp_entry_t* entry = cache_tbl;
    for (int i = 0; i < ARP_CACHE_SIZE; i++, entry++)
    {
        if ((entry->state != NET_ARP_WATTING) && (entry->state != NET_ARP_RESOLVED))
            continue;

        display_arp_entry(entry);
    }
}

static void arp_pkt_display(arp_pkt_t* packet)
{
    uint16_t opcode = x_ntohs(packet->opcode);

    plat_printf("---------- arp packet ----------------\n");
    plat_printf("    htype: %d\n", x_ntohs(packet->htype));
    plat_printf("    ptype: %04x\n", x_ntohs(packet->ptype));
    plat_printf("    hlen: %d\n", packet->hwlen);
    plat_printf("    plen: %d\n", packet->plen);
    plat_printf("    type: %d ", opcode);
    switch (opcode)
    {
    case ARP_REQUEST:
        plat_printf("request\n");
        break;
    case ARP_REPLAY:
        plat_printf("replay\n");
        break;
    default:
        plat_printf("unknown\n");
        break;
    }

    dbg_dump_ip_buf("    sender:", packet->sender_paddr);
    dbg_dump_hwaddr("   mac:", packet->sender_hwaddr, ETHER_HWA_SIZE);
    dbg_dump_ip_buf("\n    target:", packet->target_paddr);
    dbg_dump_hwaddr("   mac:", packet->target_hwaddr, ETHER_HWA_SIZE);
    plat_printf("\n---------- arp end ----------------\n");
}
#else
#define arp_pkt_display(packet)
#define display_arp_tbl() 
#endif

/**
 * 清除一个arp表项内附带的数据包
 * @param entry 被清除的表项
 */
static void cache_clear_all(arp_entry_t* entry)
{
    dbg_info(DBG_ARP, "clear packet");

    nlist_node_t* first;
    // 从entry内的buflist这个链表的最后一个一点一点的移除
    while((first = nlist_remove_first(&entry->buf_list)))
    {
        pktbuf_t* buf = nlist_entry(first, pktbuf_t, node);
        pktbuf_free(buf);
    }
}

/**
 * 把一个arp表项中的buf全部发送出去
 * @param 待发送的arp表项
 * @return net_err错误类型
 */
static net_err_t cache_send_all(arp_entry_t* entry)
{
    dbg_info(DBG_ARP, "send all packet");

    nlist_node_t* first;
    // 从entry内的buflist这个链表的最后一个一点一点的发送
    while ((first = nlist_remove_first(&entry->buf_list)))
    {
        pktbuf_t* buf = nlist_entry(first, pktbuf_t, node);
        net_err_t err = ether_raw_out(entry->netif, NET_PROTOCOL_IPV4, entry->hwaddr, buf);
        if (err < 0)
            pktbuf_free(buf);
    }

    return NET_ERR_OK;
}

/**
 * 从总的arp待分配表中拿一个arp表项
 * 这里取了个巧，原本当最后一个移除失败的时候就不干了，但是实际上这种情况发生的次数很少，即使发生了，也会在很短的时间内自行恢复
 * 所以我给了它第二次机会，当最后一个移除失败的情况下，还允许再来一次
 * @param force 当arp待分配表已经满了的时候，是否允许删除最后一个arp表项来强行拿到一个新的arp表项
 * @param reload 当arp待分配表满了，并且最后一个还移除失败的时候，是否允许再尝试一次
 * @return arp表项
 */
static arp_entry_t* cache_alloc (int force, int reload)
{
    arp_entry_t* entry = mblock_alloc(&cache_mblock, -1);
    if (!entry && force)
    {
        nlist_node_t* node = nlist_remove_last(&cache_list);
        if (!node)
        {
            dbg_WARNING(DBG_ARP, "alloc arp entry exceptional, will try again");
            // 如果reload>0，则说明这次调用时递归的调用，第二次再失败就不能给机会了
            if (reload > 0)
            {
                dbg_WARNING(DBG_ARP, "alloc arp entry failed.");
                return (arp_entry_t*)0;
            }
            // 递归一下，让协议栈再尝试一次
            cache_alloc(force, reload++);
        }

        // 最后一个表项从链表中删除成功，但是注意，此时这个节点内的数据还没删除，所以需要手动删除一下数据
        // 其中最重要的就是这个表项中挂着的数据包buf
        //由于buf是一个链表，直接使用memset清不掉，所以使用了cache_clear_all这个函数来清除这个数据包
        entry = nlist_entry(node, arp_entry_t, node);
        cache_clear_all(entry);
    }

    // 走到这里说明拿到了一个表项，初始化一下，后续接到链表上是别的函数的工作了
    if (entry)
    {
        plat_memset(entry, 0, sizeof(arp_entry_t));
        entry->state = NET_APR_FREE;
        nlist_node_init(&entry->node);
        nlist_init(&entry->buf_list);
    }

    return entry;
}

/**
 * 从arp表中删除一个指定的表项
 * @param entry 待删除的表项
 */
static void cache_free(arp_entry_t* entry)
{
    cache_clear_all(entry);
    nlist_remove(&cache_list, &entry->node);
    mblock_free(&cache_mblock, entry);
}

/**
 * 在arp表中查找一个arp表项
 * @param ip arp表项的ip
 * @return 找到的arp表项
 */
static arp_entry_t* cache_find (uint8_t* ip)
{
    nlist_node_t* node;
    nlist_for_each(node, &cache_list)
    {
        arp_entry_t* entry = nlist_entry(node, arp_entry_t, node);
        if (plat_memcmp(ip, entry->paddr, IPV4_ADDR_SIZE) == 0)
        {
            nlist_remove(&cache_list, &entry->node);
            nlist_insert_first(&cache_list, &entry->node);
            return entry;
        }
    }

    return (arp_entry_t*)0;
}

static void cache_entry_set (arp_entry_t* entry, const uint8_t* hwaddr, uint8_t* ip, netif_t* netif, int status)
{
    plat_memcpy(entry->hwaddr, hwaddr, ETHER_HWA_SIZE);
    plat_memcpy(entry->paddr, ip, IPV4_ADDR_SIZE);
    entry->state = status;
    entry->netif = netif;
    entry->tmo = 0;
    entry->retry = 0;
}

/**
 * 在arp表中插入一个arp表项
 * @param netif 网卡
 * @param ip 表项中的ip
 * @param hwaddr 表项中的mac
 * @param force 插入时如果arp待分配表中没有空位了，是否删除最后一个
 * @return net_err错误类型
 */
static net_err_t cache_insert (netif_t* netif, uint8_t* ip, uint8_t* hwaddr, int force)
{
    if (*(uint32_t*)ip == 0)
        return NET_ERR_NOT_SUPPORT;

    // 先看arp表中有没有
    arp_entry_t* entry = cache_find(ip);
    if (!entry)
    {
        // 如果没有，就重新分配一个
        entry = cache_alloc(force, 0);
        if (!entry)
            return NET_ERR_NONE;
        
        // 分配完之后设置表项的内容，再把它丢到arp表的头部
        cache_entry_set(entry, hwaddr, ip, netif, NET_ARP_RESOLVED);
        nlist_insert_first(&cache_list, &entry->node);
    }
    else
    {
        // 走到这说明arp表中已存在该表项，更新一下值，然后如果不是头部就把它丢到头部
        cache_entry_set(entry, hwaddr, ip, netif, NET_ARP_RESOLVED);
        if (nlist_first(&cache_list) != &entry->node)
        {
            nlist_remove(&cache_list, &entry->node);
            nlist_insert_first(&cache_list, &entry->node);
        }

        // 还要记得把之前表项中缓存的数据发出去
        net_err_t err = cache_send_all(entry);
        if (err < 0)
        {
            dbg_ERROR(DBG_ARP, "send packet failed.");
            return err;
        }
    }

    display_arp_tbl();
    return NET_ERR_OK;
}

static net_err_t cache_init(void)
{
    nlist_init(&cache_list);

    net_err_t err = mblock_init(&cache_mblock, &cache_tbl, sizeof(arp_entry_t), ARP_CACHE_SIZE, NLOCKER_NONE);
    if (err < 0)
    {
        return err;
    }

    return NET_ERR_OK;
}

net_err_t arp_init (void)
{
    net_err_t err = cache_init();
    if (err < 0)
    {
        dbg_ERROR(DBG_ARP, "arp cache init failed.");
        return err;
    }
    return err;
}

/**
 * 发送一个arp请求包
 * @param netif 网卡
 * @param dest 想知道的ip地址
 * @return net_err错误类型
 */
net_err_t arp_make_rquest(netif_t* netif, const ipaddr_t* dest)
{
    uint8_t* ip = (uint8_t*)dest->a_addr;
    
    ip[0] = 0x1;
    cache_insert(netif, ip ,netif->hwadder.addr, 1);
    ip[0] = 0x2;
    cache_insert(netif, ip ,netif->hwadder.addr, 1);
    ip[0] = 0x3;
    cache_insert(netif, ip ,netif->hwadder.addr, 1);
    cache_insert(netif, ip ,netif->hwadder.addr, 1);

    pktbuf_t* buf = pktbuf_alloc(sizeof(arp_pkt_t));
    if(!buf)
    {
        dbg_ERROR(DBG_ARP, "alloc pktbuf failed");
        return NET_ERR_NONE;
    }

    pktbuf_set_cont(buf, sizeof(arp_pkt_t));
    arp_pkt_t* arp_packet = (arp_pkt_t*)pktbuf_data(buf);
    arp_packet->htype = x_htons(ARP_HW_ETHER);
    arp_packet->ptype = x_htons(NET_PROTOCOL_IPV4);
    arp_packet->hwlen = ETHER_HWA_SIZE;
    arp_packet->plen = IPV4_ADDR_SIZE;
    arp_packet->opcode = x_htons(ARP_REQUEST);
    plat_memcpy(arp_packet->sender_hwaddr, netif->hwadder.addr, ETHER_HWA_SIZE);
    ipaddr_to_buf(&netif->ipaddr, arp_packet->sender_paddr);
    plat_memset(arp_packet->target_hwaddr, 0, sizeof(ETHER_HWA_SIZE));
    ipaddr_to_buf(dest, arp_packet->target_paddr);

    arp_pkt_display(arp_packet);

    net_err_t err = ether_raw_out(netif, NET_PROTOCOL_ARP, ether_broadcast_addr(), buf);
    if (err < 0)
        pktbuf_free(buf);
    return err;
}

/**
 * 发送一个免费arp报文
 * @param netif 网卡
 * @return net_err错误类型
 */
net_err_t arp_make_gratuitous(netif_t* netif)
{
    dbg_info(DBG_ARP, "send an gratuitous arp...");
    return arp_make_rquest(netif, &netif->ipaddr);
}

/**
 * 发送一个arp响应包，这里直接改一改上面捕获到的arp请求包即可
 * 也不需要释放，因为这个包最终会被丢到输出队列里，输出队列自会释放
 * @param netif 网卡
 * @param buf 上面捕获到的arp请求包
 * @return net_err错误类型
 */
net_err_t arp_make_reply (netif_t* netif, pktbuf_t* buf)
{
    arp_pkt_t* arp_packet = (arp_pkt_t*)pktbuf_data(buf);

    // 修改包中的一些内容
    arp_packet->opcode = x_htons(ARP_REPLAY);
    plat_memcpy(arp_packet->target_hwaddr, arp_packet->sender_hwaddr, ETHER_HWA_SIZE);
    plat_memcpy(arp_packet->target_paddr, arp_packet->sender_paddr, IPV4_ADDR_SIZE);
    plat_memcpy(arp_packet->sender_hwaddr, netif->hwadder.addr, ETHER_HWA_SIZE);
    ipaddr_to_buf(&netif->ipaddr,  arp_packet->sender_paddr);

    arp_pkt_display(arp_packet);

    return ether_raw_out(netif, NET_PROTOCOL_ARP, arp_packet->target_hwaddr, buf);
}

/**
 * 判断一个arp包是否合法，使用了多种方法判断
 * 下层协议类型是否是以太网，上层协议类型是否是ipv4
 * mac地址和ipv4地址长度是否合法
 * opcode是否是正常的三种
 */
static net_err_t is_pkt_ok(arp_pkt_t* arp_packet, uint16_t size, netif_t* netif)
{
    if (size < sizeof(arp_pkt_t))
    {
        dbg_WARNING(DBG_ARP, "packet size error");
    }

    if (x_ntohs(arp_packet->htype != ARP_HW_ETHER)
    || (arp_packet->hwlen != ETHER_HWA_SIZE)
    || (x_htons(arp_packet->ptype) != NET_PROTOCOL_IPV4)
    || (arp_packet->plen != IPV4_ADDR_SIZE))
    {
        dbg_WARNING(DBG_ARP, "packet incorroect");
        return NET_ERR_NOT_SUPPORT;
    }

    uint16_t opcode = x_ntohs(arp_packet->opcode);
    if ((opcode != ARP_REPLAY) && (opcode != ARP_REQUEST))
    {
        dbg_WARNING(DBG_ARP, "unknown opcode");
        return NET_ERR_NOT_SUPPORT;
    }
    
    return NET_ERR_OK;
}

/**
 * 数据链路层收到一个包并确定为arp包后，直接调用这个函数，这是处理arp包的第一手函数
 * @param netif 网卡
 * @param buf 数据链路层捕获到的arp请求
 * @return net_err错误类型
 */
net_err_t arp_in (netif_t* netif, pktbuf_t* buf)
{
    dbg_info(DBG_ARP, "arp in");

    net_err_t err = pktbuf_set_cont(buf, sizeof(arp_pkt_t));
    if (err < 0)
        return err;
    
    arp_pkt_t* arp_packet = (arp_pkt_t*)pktbuf_data(buf);
    if (is_pkt_ok(arp_packet, buf->total_size, netif) != NET_ERR_OK)
        return err;
    
    arp_pkt_display(arp_packet);

    if (x_ntohs(arp_packet->opcode == ARP_REQUEST))
    {
        dbg_info(DBG_ARP, "arp request, send reply");
        return arp_make_reply(netif, buf);
    }

    pktbuf_free(buf);
    return NET_ERR_OK;
}

