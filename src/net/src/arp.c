#include "arp.h"
#include "debug.h"
#include "mblock.h"
#include "pktbuf.h"
#include "tools.h"
#include "protocol.h"
#include "sys.h"
#include "timer.h"

static arp_entry_t cache_tbl[ARP_CACHE_SIZE];       // arp可使用的系统中所有的内存
static mblock_t cache_mblock;                       // 用来分配上面的数据
static nlist_t cache_list;                           // arp链表
static net_timer_t cache_timer;

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
#define display_arp_entry(entry)
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

/**
 * 定时的去把arp表项超时，第一次超时后会将状态修改为watting
 * 随后每次扫到watting的时候，就将retry--，当retry-到0的时候，就要将这个包释放
 * 目前定义的retry是3，每1s扫一次，也就是说当一个包超时后，会每隔1秒钟发一次arp请求
 * 一共发三次，如果三次都没收到并处理对应的arp回应，那么就代表了该表项需要被free了
 * @param timer 被调用的定时器
 * @param arg 定时器要去的参数而已，其实没用到
 */
static void arp_cache_tmo (net_timer_t * timer, void * arg)
{
    int change_cnt = 0;     // 用来计数多少个包状态被改变了
    nlist_node_t* curr;
    nlist_node_t* next;

    for (curr = cache_list.first; curr; curr = next)
    {
        next = nlist_node_next(curr);

        arp_entry_t* entry = nlist_entry(curr, arp_entry_t, node);
        ipaddr_t ipaddr;
        ipaddr_from_buf(&ipaddr, entry->paddr);
        if (--entry <= 0)
        {
            change_cnt++;
            switch (entry->state)
            {
            case NET_ARP_RESOLVED:
            {
                dbg_info(DBG_ARP, "state to pending:");
                display_arp_entry(entry);
    
                entry->state = NET_ARP_WATTING;
                entry->tmo = ARP_ENTRY_PENDING_TMO;
                entry->retry = ARP_ENTRY_RETRY_CNT;
                arp_make_rquest(entry->netif, &ipaddr);
                break;
            }
            case NET_ARP_WATTING:
            {
                if (--entry->retry == 0)
                {
                    // retry为0时arp表项都还没更新，直接free
                    dbg_info(DBG_ARP, "pending tmo, free it");
                    display_arp_entry(entry);
                    cache_free(entry);
                }
                else
                {
                    // retry还没为0，打个信息再发一次arp的请求包
                    dbg_info(DBG_ARP, "pending tmo, send request.");
                    display_arp_entry(entry);

                    entry->tmo = ARP_ENTRY_PENDING_TMO;
                    arp_make_rquest(entry->netif, &ipaddr);
                }
                break;
            }
                
            // 按理说除了resoled和watting以外还应该有一个free状态，但是实际上free状态只会在arp表项还没链到链表上时出现
            // 我们这里遍历的是arp链表，所以是不会遍历到free状态的，即使遍历到free状态，也依然是异常的
            default:
            {
                dbg_ERROR(DBG_ARP, "unknown arp state");
                display_arp_entry(entry);
                break;
            }
            }
        }
    }

    if (change_cnt)
    {
        dbg_info(DBG_ARP, "%d arp entry changed.", change_cnt);
        display_arp_tbl();
    }
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
        dbg_ERROR(DBG_ARP, "arp cache init failed.");
        return err;
    }

    err =net_timer_add(&cache_timer, "arp timer", arp_cache_tmo, (void*)0, ARP_TIMER_TMO * 1000, NET_TIMER_RELOAD);
    if (err < 0)
    {
        dbg_ERROR(DBG_ARP, "create timer failed: %d", err);
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

    if ((x_ntohs(arp_packet->htype) != ARP_HW_ETHER)
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
 * 当数据链路层需要发送一个ip包时，就会调用该函数，这个函数大体思路如下:
 * 首先先看arp表里有没有，如果有，并且表项状态是正确的，就直接调用底层发送函数直接把包发出去
 * 如果表项芝士存在，但是不存在mac地址，那就参照下面的注释
 * 如果表项不存在，那么申请一个，其他的思路和上面一样
 * @param netif 数据从哪个网卡发出去
 * @param ipaddr 发送到哪个ip地址去
 * @param buf 数据链路层待发送的ip数据包
 * @return net_err错误类型
 */
net_err_t arp_resolve (netif_t* netif, const ipaddr_t* ipaddr, pktbuf_t* buf)
{
    // 需要转一下ip的结构
    uint8_t ip_buf[IPV4_ADDR_SIZE];
    ipaddr_to_buf(ipaddr, ip_buf);

    // 先判断一下目标地址是否是本网络的
    if (ipaddr_is_direct_broadcast(&netif->ipaddr, &netif->netmask, ipaddr) || ipaddr_is_local_broadcast(ipaddr))
        ether_raw_out(netif, NET_PROTOCOL_IPV4, ether_broadcast_addr(), buf);

    // 查表看看能不能查到
    arp_entry_t* entry = cache_find(ip_buf);
    if (entry)
    {
        dbg_info(DBG_ARP, "found an arp entry.");
        // 如果查到了，得看看这个表项内有没有mac地址，如果有，直接对着这个mac发就完事了
        if (entry->state == NET_ARP_RESOLVED)
            return ether_raw_out(netif, NET_PROTOCOL_IPV4, entry->hwaddr, buf);
        
        // 如果存在表项但是不存在mac，就说明这个表项的arp请求刚刚发出去了，但是还没收到回复
        // 那么我们直接把数据包丢到这个表项的buf里就ok了，回头收到回复的时候会把buf全发出去的
        // 但是需要保证一个arp表项上链的buf不能太多，否则整个协议栈的buf可能会进入一个黑洞表项
        if (nlist_count(&entry->buf_list) <= ARP_MAX_PKT_WAIT)
        {
            dbg_info(DBG_ARP, "insert buf to arp entry");
            nlist_insert_last(&entry->buf_list, &buf->node);
            return NET_ERR_OK;
        }
        else
        {
            dbg_info(DBG_ARP, "too many bufs on this arp entry, entry is: %d.%d.%d.%d", ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]);
            return NET_ERR_FULL;
        }
    }
    // 走到这说明没查到
    dbg_info(DBG_ARP, "not find arp entry, The ip you are trying to find is: %d.%d.%d.%d, The protocol stack will send an arp requset", ip_buf[0], ip_buf[1], ip_buf[2], ip_buf[3]);
    
    entry = cache_alloc(1, 0);
    if (entry == (arp_entry_t*)0)
    {
        dbg_ERROR(DBG_ARP, "alloc arp failed.");
        return NET_ERR_NONE;
    }

    // 走到这说明拿到了一个新的包
    cache_entry_set(entry, emptry_hwaddr, ip_buf, netif, NET_ARP_WATTING);
    nlist_insert_first(&cache_list, &entry->node);
    nlist_insert_last(&entry->buf_list, &buf->node);

    display_arp_entry(entry);
    return arp_make_rquest(netif, ipaddr);
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

    // 如果收到一个arp包，不管是不是发给自己的，不管是回应还是请求，都把对面的mac地址记录下来
    ipaddr_t target_ip;
    ipaddr_from_buf(&target_ip, arp_packet->target_paddr);

    if (ipaddr_is_equal(&target_ip, &netif->ipaddr))
    {
        cache_insert(netif, arp_packet->sender_paddr, arp_packet->sender_hwaddr, 1);
        if (x_ntohs(arp_packet->opcode == ARP_REQUEST))
        {
            dbg_info(DBG_ARP, "arp request, send reply");
            return arp_make_reply(netif, buf);
        }
    }
    else
    {
        dbg_info(DBG_ARP, "recieve an arp, but it's not for me");
        // 不是发给自己的，就没有必要在arp待使用表项不足的情况下强行插入了
        cache_insert(netif, arp_packet->sender_paddr, arp_packet->sender_hwaddr, 0);
    }

    pktbuf_free(buf);
    return NET_ERR_OK;
}

void arp_clear (netif_t* netif)
{
    nlist_node_t* curr;
    nlist_node_t* next;

    for (curr = nlist_first(&cache_list); curr; curr = next)
    {
        next = nlist_node_next(curr);
        arp_entry_t* entry = nlist_entry(curr, arp_entry_t, node);

        if (entry->netif == netif)
        {
            nlist_remove(&cache_list, curr);
        }
    }
}