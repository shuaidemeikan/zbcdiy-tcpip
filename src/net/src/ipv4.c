#include "ipv4.h"
#include "debug.h"
#include "tools.h"
#include "protocol.h"
#include "icmpv4.h"
#include "mblock.h"
#include "timer.h"
#include "raw.h"
#include "udp.h"
#include "tcp_in.h"

static uint16_t packet_id = 0;

static ip_frag_t frag_array[IP_FRAGS_MAX_NR];
static mblock_t frag_mblock;
static nlist_t frag_list;
static net_timer_t frag_timer;

static nlist_t rt_list;
static rentry_t rt_table[IP_RTTABLE_SIZE];
static mblock_t rt_mblock;

#if DBG_DISP_ENABLED(DBG_IP)
void rt_nlist_display (void) {
    plat_printf("rt table\n");

    nlist_node_t * node;
    nlist_for_each(node, &rt_list) {
        rentry_t * entry = nlist_entry(node, rentry_t, node);
        dbg_dump_ip("   net: ", &entry->net);
        dbg_dump_ip("   mask: ", &entry->mask);
        dbg_dump_ip("   next_hop: ", &entry->next_hop);
        plat_printf("    netif: %s\n", entry->netif->name);
    }
}

#else
#define rt_nlist_display()
#endif

void rt_init (void)
{
    nlist_init(&rt_list);
    mblock_init(&rt_mblock, rt_table, sizeof(rentry_t), IP_RTTABLE_SIZE, NLOCKER_NONE);
}

void rt_add (ipaddr_t* net, ipaddr_t* mask, ipaddr_t* next_hop, netif_t* netif)
{
    rentry_t* entry = (rentry_t*)mblock_alloc(&rt_mblock, -1);
    if (!entry)
    {
        dbg_warning(DBG_IP, "mblock alloc failed");
        return;
    }

    ipaddr_copy(&entry->net, net);
    ipaddr_copy(&entry->mask, mask);
    ipaddr_copy(&entry->next_hop, next_hop);
    entry->mask_1_cnt = ipaddr_1_cnt(mask);
    entry->netif = netif;

    nlist_insert_last(&rt_list, &entry->node);
    rt_nlist_display();
}

void rt_remove (ipaddr_t* net, ipaddr_t* mask)
{
    nlist_node_t* node;
    nlist_for_each(node, &rt_list)
    {
        rentry_t* entry = nlist_entry(node, rentry_t, node);
        if (ipaddr_is_equal(&entry->net, net) == 0 && ipaddr_is_equal(&entry->mask, mask) == 0)
        {
            nlist_remove(&rt_list, &entry->node);
            mblock_free(&rt_mblock, entry); 
            return;
        }
    }
    rt_nlist_display();
}

rentry_t* rt_find (ipaddr_t* ip)
{
    rentry_t* curr_entry = (rentry_t*)0;
    nlist_node_t* node;
    nlist_for_each(node, &rt_list)
    {
        rentry_t* entry = nlist_entry(node, rentry_t, node);
        uint32_t ip_network_number_uint32 = get_network(ip, &entry->mask);
        ipaddr_t ip_network_addr_ipaddr;
        ipaddr_from_buf(&ip_network_addr_ipaddr, (uint8_t*)&ip_network_number_uint32);
        if (!ipaddr_is_equal(&entry->net, &ip_network_addr_ipaddr))
            continue;

        if (!curr_entry || (curr_entry->mask_1_cnt < entry->mask_1_cnt))
            curr_entry = entry;
    }
    return curr_entry;
}

/**
 * 获得一个ip数据包数据部分的大小，也就是不含头部多大
 * @param pkt 待判断的ip数据包
 * @return net_err错误类型
 */
static int get_data_size (ipv4_pkt_t* pkt)
{
    return pkt->hdr.total_len - ipv4_hdr_size(pkt);
}

/**
 * 获得一个ip数据包的分片偏移
 * @param pkt 待判断的ip数据包
 * @return net_err错误类型
 */
static uint16_t get_frag_start (ipv4_pkt_t* pkt)
{
    return pkt->hdr.frag_offset * 8;
}

/**
 * 获得一个ip数据包的offset长度，也就是这个ip数据包的offset是多少到多少
 * @param pkt 待判断的ip数据包
 * @return net_err错误类型
 */
static uint16_t get_frag_end (ipv4_pkt_t* pkt)
{
    return get_frag_start(pkt) + get_data_size(pkt);
}

#if DBG_DISP_ENABLED(DBG_IP)
static void display_ip_pkt(ipv4_pkt_t* pkt)
{
    ipv4_hdr_t* ip_hdr = &pkt->hdr;
    plat_printf("--------------ip ---------------\n");
    plat_printf("    version: %d\n", ip_hdr->version);
    plat_printf("    header len: %d\n", ipv4_hdr_size(pkt));
    plat_printf("    total len: %d\n", ip_hdr->total_len);
    plat_printf("    id: %d\n", ip_hdr->id);
    plat_printf("    ttl: %d\n", ip_hdr->ttl);
    plat_printf("    frag offset: %d\n", ip_hdr->frag_offset);
    plat_printf("    frag more: %d\n", ip_hdr->more);
    plat_printf("    protocol: %d\n", ip_hdr->protocol);
    plat_printf("    checksum: %d\n", ip_hdr->hdr_checksum);
    dbg_dump_ip_buf("     src ip:", ip_hdr->src_ip);   
    dbg_dump_ip_buf(" dest ip:", ip_hdr->dest_ip);
    plat_printf("\n--------------ip end ---------------\n");
}

static void display_ip_frags (void)
{
    int f_index = 0;
    nlist_node_t* f_node;
    nlist_for_each(f_node, &frag_list)
    {
        ip_frag_t* frag = nlist_entry(f_node, ip_frag_t, node);

        plat_printf("[%d]: \n", f_index++);
        dbg_dump_ip("   ip:", &frag->ip);
        plat_printf("   tmp: %d\n", frag->id);
        plat_printf("   tmo: %d\n", frag->tmo);
        plat_printf("   bufs: %d\n", nlist_count(&frag->buf_list));

        plat_printf("   bufs:\n");
        nlist_node_t* p_node;
        int p_index = 0;
        nlist_for_each(p_node, &frag->buf_list)
        {
            pktbuf_t* buf = nlist_entry(p_node, pktbuf_t, node);
            ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
            plat_printf("   B%d:[%d-%d],    ", p_index++, get_frag_start(pkt), get_frag_end(pkt));
        }
        plat_printf("\n");
    }
}
#else
#define display_ip_pkt(a)
#define display_ip_frags()
#endif

/**
 * 释放一个分片缓存内串着的待合并的数据包
 * @param frag 待释放数据包的分片缓存
 */
static void frag_free_buf_list (ip_frag_t* frag)
{
    nlist_node_t* node;
    while ((node = nlist_remove_first(&frag->buf_list)))
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(buf);
    }
}

/**
 * 分配一个ip分片缓存
 * @return ip_frag_t*类型的分片结构
 */
static ip_frag_t* frag_alloc (void)
{
    ip_frag_t* frag = mblock_alloc(&frag_mblock, -1);
    // 如果获得不到，就把已经在表里的分片缓存里最晚没更新的分片给释放掉，用来当新的分片结构
    if (!frag)
    {
        nlist_node_t* node = nlist_remove_last(&frag_list);
        frag = nlist_entry(node, ip_frag_t, node);
        if (frag)
        {
            frag_free_buf_list(frag);
        }
    }
    return frag;
}

/**
 * 释放一个分片缓存
 * @param pkt 待释放的分片缓存
 */
static void frag_free (ip_frag_t* frag)
{
    frag_free_buf_list(frag);
    nlist_remove(&frag_list, &frag->node);
    mblock_free(&frag_mblock, frag);
}

static inline void iphdr_ntohs (ipv4_pkt_t* pkt)
{
    pkt->hdr.total_len = x_ntohs(pkt->hdr.total_len);
    pkt->hdr.id = x_ntohs(pkt->hdr.id);
    pkt->hdr.frag_all = x_ntohs(pkt->hdr.frag_all);
}

static inline void iphdr_htons (ipv4_pkt_t* pkt)
{
    pkt->hdr.total_len = x_htons(pkt->hdr.total_len);
    pkt->hdr.id = x_htons(pkt->hdr.id);
    pkt->hdr.frag_all = x_htons(pkt->hdr.frag_all);
}

static net_err_t is_pkt_ok (ipv4_pkt_t* pkt, int size, netif_t* netif)
{
    // 判断版本号
    if (pkt->hdr.version != NET_VERSION_IPV4)
    {
        dbg_WARNING(DBG_IP, "invalid ip version");
        return NET_ERR_NOT_SUPPORT;
    }

    // 判断ip包头长度
    if (ipv4_hdr_size(pkt) < sizeof(ipv4_hdr_t))
    {
        dbg_WARNING(DBG_IP, "ipv4 header size error");
        return NET_ERR_SIZE;
    }

    // 判断整个数据包的长度，首先不能小于包头，其次不能大于总大小
    int total_size = x_ntohs(pkt->hdr.total_len);
    if ((total_size < sizeof(ipv4_hdr_t)) || (size < total_size))
    {
        dbg_WARNING(DBG_IP, "ipv4 packet size error");
        return NET_ERR_SIZE;
    }
    // 校验和检测
    if (pkt->hdr.hdr_checksum) 
    {
        uint16_t c = checksum16(0, pkt, ipv4_hdr_size(pkt), 0, 1);
        if (c != 0) 
        {
            dbg_WARNING(DBG_IP, "bad checksum");
            return NET_ERR_BROKEN;
        }
    }

    // 一切正常
    return NET_ERR_OK;
    
}

/**
 * 往全局的分片缓存链表里插入一个分片缓存，并在此之前初始化它
 * @param frag 待初始化和插入的分片缓存
 * @param ip 该分片缓存内的数据包来自于哪个ip
 * @param id 该分片缓存内的数据包来自于哪个id
 */
static void frag_add (ip_frag_t* frag, ipaddr_t* ip, uint16_t id)
{
    ipaddr_copy(&frag->ip, ip);
    frag->tmo = IP_FRAG_TMO / IP_FRAG_SCAN_PERIOD;
    frag->id = id;
    nlist_node_init(&frag->node);
    nlist_init(&frag->buf_list);

    nlist_insert_first(&frag_list, &frag->node);
}

/**
 * 查找一个分片缓存是否在全局分片缓存链表里
 * @param ip 待查找的分片缓存ip
 * @param id 待查找的分片缓存id
 * @return 查找到的分片缓存
 */
static ip_frag_t* frag_find (ipaddr_t* ip, uint16_t id)
{
    nlist_node_t* curr;
    nlist_for_each(curr, &frag_list)
    {
        ip_frag_t* frag = nlist_entry(curr, ip_frag_t, node);
        if (ipaddr_is_equal(&frag->ip, ip) && (id == frag->id))
        {
            // 查找了，就说明很快就会用到它了，所以先把它放到链表的前面
            if (nlist_first(&frag_list) != curr)
            {
                nlist_remove(&frag_list, curr);
                nlist_insert_first(&frag_list, curr);
            }
            return frag;
        }
    }
    return (ip_frag_t*)0;
}

/**
 * 往一个分片缓存内插入一个buf
 * @param frag 待被插入的分片缓存
 * @param buf 待插入的buf
 * @param pkt 被插入的buf来自的pkt
 * @return net_err错误类型
 */
static net_err_t frag_insert (ip_frag_t* frag, pktbuf_t* buf, ipv4_pkt_t* pkt)
{
    // 一个分片缓存内能存储的最大buf数是有限的，防止整个协议栈的pktbuf结构全部消耗到这里了，超出数量的分片就是协议栈不支持
    if (nlist_count(&frag->buf_list) >= IP_FRAG_MAX_BUF_NR)
    {
        dbg_WARNING(DBG_IP, "too many bufs on frag");
        frag_free(frag);
        return NET_ERR_FULL;
    }

    nlist_node_t* node;
    nlist_for_each(node, &frag->buf_list)
    {
        pktbuf_t* curr_buf = nlist_entry(node, pktbuf_t, node);
        ipv4_pkt_t* curr_pkt = (ipv4_pkt_t*)pktbuf_data(curr_buf);

        uint16_t curr_start = get_frag_start(curr_pkt);
        uint16_t pkt_start = get_frag_start(pkt);
        // 当前数据包的offset不可能和分片缓存内已经有的数据包的offset相同
        // 所以出现这种情况，可以判断为是中间网络有bug，把某个包发了两次
        if (pkt_start == curr_start)
            return NET_ERR_EXIST;
        // 当新来的数据包offset比遍历到的数据包的offset小，那么就说明这个数据包应该是排在当前遍历到的数据包前面的
        else if (pkt_start <= curr_start)
        {
            nlist_node_t* pre = nlist_node_pre(node);
            // 如果当前遍历到的数据包前面没雨数据包了，那么直接调用头插入就ok了
            if (pre)
                nlist_insert_after(&frag->buf_list, pre, &buf->node);
            else
                nlist_insert_first(&frag->buf_list, &buf->node);
            return NET_ERR_OK;
        }
    }
    // 如果没有出现上面两种情况，那么直接把数据包插在整个链表的末尾就可以了
    nlist_insert_last(&frag->buf_list, &buf->node);
    return NET_ERR_OK;
}

/**
 * 判断一个分片缓存是否已经收齐，但是在这里不做最后的判断，这里只是把最后一个数据包的more返回出去，由上层函数来判断
 * @param frag 待判断的分片缓存
 * @return more的值
 */
static int frag_is_all_arrived (ip_frag_t* frag)
{
    int offset = 0;

    nlist_node_t* node;
    ipv4_pkt_t* pkt = (ipv4_pkt_t*)0;
    nlist_for_each(node, &frag->buf_list)
    {
        pktbuf_t* buf = nlist_entry(node, pktbuf_t, node);
        pkt = (ipv4_pkt_t*)pktbuf_data(buf);
        if (get_frag_start(pkt) != offset)
            return 0;
        
        offset += get_data_size(pkt);
    }
    return pkt ? !pkt->hdr.more : 0;
}

/**
 * 将一个分片缓存内的数据包合并成一个pktbuf结构，并返回
 * @param frag 待合成的分片缓存
 * @return 合成后的pktbuf
 */
static pktbuf_t* frag_join (ip_frag_t* frag)
{
    pktbuf_t* target = (pktbuf_t*)0;
    nlist_node_t* node;
    while (node = nlist_remove_first(&frag->buf_list))
    {
        pktbuf_t* curr = nlist_entry(node, pktbuf_t, node);
        // 如果是第一个，那么直接把target指向这个就ok
        if (!target)
        {
            target = curr;
            continue;
        }

        // 移除当前遍历到的数据包包头
        net_err_t err = pktbuf_remove_header(curr, ipv4_hdr_size((ipv4_pkt_t*)pktbuf_data(curr)));
        if (err < 0)
        {
            dbg_ERROR(DBG_IP, "remove hdr failed.");
            // 由于curr已经被移除了，所以释放我们必须在这里完成，否则一旦返回，curr就不会有被释放的可能，下面也是同理
            pktbuf_free(curr);
            goto free_and_return;
        }

        // 把新的数据包串到target上
        err = pktbuf_join(target, curr);
        if (err < 0)
        {
            dbg_ERROR(DBG_IP, "join ip frag failed.");
            pktbuf_free(curr);
            goto free_and_return;
        }
    }
    // 走到这里，说明所有数据包全部正确的串上了，把当前分片缓存释放掉，然后返回合成好的pktbuf
    frag_free(frag);
    return target;

free_and_return:
    // 如果上面出问题，那么target也是需要被回收的
    if (target)
        pktbuf_free(target);
    // 上面任何一个步骤失败，都会导致该分片缓存寄，所以分片缓存也需要被释放
    frag_free(frag);
    return (pktbuf_t*)0;
}

static void frag_tmo (net_timer_t* timer, void* arg)
{
    nlist_node_t* curr;
    nlist_node_t* next;
    for (curr = nlist_first(&frag_list); curr; curr = next)
    {
        next = nlist_node_next(curr);

        ip_frag_t* frag = nlist_entry(curr, ip_frag_t, node);
        if (--frag->tmo <= 0)
            frag_free(frag);
    }
}

static net_err_t frag_init (void)
{
    nlist_init(&frag_list);
    mblock_init(&frag_mblock, frag_array, sizeof(ip_frag_t), IP_FRAGS_MAX_NR, NLOCKER_NONE);

    net_err_t err = net_timer_add(&frag_timer, "frag timer", frag_tmo, (void*)0, IP_FRAG_SCAN_PERIOD * 1000, NET_TIMER_RELOAD);
    if (err < 0)
    {
        dbg_ERROR(DBG_IP, "create frag timer failed!");
        return err;
    }
    return NET_ERR_OK;
}

/**
 * IPV4的初始化函数
 * @return net_err错误类型
 */
net_err_t ipv4_init (void)
{
    dbg_info(DBG_IP, "init ip\n");

    net_err_t err = frag_init();
    if (err < 0)
    {
        dbg_ERROR(DBG_IP, "frag init failed");
        return err;
    }
    //rt_init();
    dbg_info(DBG_IP, "done");
    return NET_ERR_OK;
}

/**
 * 判断一下接收到的数据包属于什么上层协议，直接丢给上层协议了，离开ip协议的最后一层函数
 * @param netif 收到数据包的网卡
 * @param buf 收到的数据包(已移除以太网包头，但是没移除ip包头)
 * @param scr_ip 数据包内的源地址
 * @param dest_ip 数据包内的目的地址
 * @return net_err错误类型
 */
net_err_t ip_normal_in(netif_t* netif, pktbuf_t* buf, ipaddr_t* src_ip, ipaddr_t* dest_ip)
{
    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    switch (pkt->hdr.protocol)
    {
    case NET_PROTOCOL_ICMPv4:
    {
        net_err_t err = icmpv4_in(src_ip, &netif->ipaddr, buf);
        if (err < 0)
            return err;
        else
            return NET_ERR_OK;
    }
    case NET_PROTOCOL_UDP:
        net_err_t err = udp_in(buf, src_ip, dest_ip);
        if (err < 0)
        {
            dbg_warning(DBG_IP, "udp in error");
            if (err == NET_ERR_UNREACH)
            {
                iphdr_htons(pkt);
                icmpv4_out_unreach(src_ip, &netif->ipaddr, ICMPv4_UNREACH_PORT, buf);
            }
            return err;
        }
        break;
    case NET_PROTOCOL_TCP:
        pktbuf_remove_header(buf, sizeof(ipv4_hdr_t));

        err = tcp_in(buf, src_ip, dest_ip);
        if (err < 0)
        {
            dbg_warning(DBG_IP, "tcp in error");
            return err;
        }
        return NET_ERR_OK;
    default:
    // 不是tcp，不是udp， 不是icmp，那就是一些莫名其妙的协议会跑到这，理论上永远不会跑到这
        dbg_warning(DBG_IP, "unknown protocol %d, drop it.\n", pkt->hdr.protocol);
        err = raw_in(buf);
        if (err < 0)
        {
            dbg_error(DBG_IP, "raw in failed!");
            return err;
        }
        return NET_ERR_OK;
    }

    //pktbuf_free(buf);
    return NET_ERR_UNREACH;
}

/**
 * 收到ip分片数据包后的处理函数，该函数调用后，将调用其他一系列函数对该分片数据包进行解析
 * 包括但不限于:该数据包属于哪一个分片缓存，该分片缓存是否已满，是否需要发送出去...
 * @param netif 收到分片数据包的网卡
 * @param buf 分片数据包本体
 * @param src_ip 该分片数据包从哪个ip来
 * @param dest_ip 该分片数据包要发到哪个ip
 * @return net_err错误类型
 */
net_err_t ip_frag_in(netif_t* netif, pktbuf_t* buf, ipaddr_t* src_ip, ipaddr_t* dest_ip)
{
    ipv4_pkt_t* curr = (ipv4_pkt_t*)pktbuf_data(buf);
    
    // 先看看这个包在全局分片缓存链表中是否存在
    ip_frag_t* frag = frag_find(src_ip, curr->hdr.id);
    if (!frag)
    {
        // 不存在，就分配一个新的分片缓存，并把其添加到全局分片缓存链表中
        frag = frag_alloc();
        frag_add(frag, src_ip, curr->hdr.id);
    }

    // 不论存不存在，走到这都会有了一个分片缓存，把buf插入到这个分片缓存里
    net_err_t err = frag_insert(frag, buf, curr);

    // 判断该分片缓存是否已收到全部的分片数据包
    if (frag_is_all_arrived(frag))
    {
        // 如果收到了，就合并分片缓存下串着的数据包
        pktbuf_t* full_buf = frag_join(frag);
        if (!full_buf)
        {
            dbg_ERROR(DBG_IP, "join ip bufs failed.");
            display_ip_frags();
            return NET_ERR_OK;
        }

        // 然后调用通用的发送接口发送出去
        err = ip_normal_in(netif, full_buf, src_ip, dest_ip);
        if (err < 0)
        {
            dbg_WARNING(DBG_IP, "ip frag in failed.", err);
            pktbuf_free(full_buf);
            return NET_ERR_OK;
        }
    }
    display_ip_frags();

    return NET_ERR_OK;
}

/**
 * 收到ip数据包后第一层用来处理的函数
 * 设置一下包头的连续性，判断一下数据包的正确与否，是否是发给自己的，最后直接丢给ip_normal_in了
 * @param 待发送的arp表项
 * @return net_err错误类型
 */
net_err_t ipv4_in (netif_t* netif, pktbuf_t* buf)
{
    dbg_info(DBG_IP, "ip in\n");

    // 设置包头连续性
    net_err_t err = pktbuf_set_cont(buf, sizeof(ipv4_hdr_t));
    if (err < 0)
    {
        dbg_ERROR(DBG_IP, "ajust header failed, err = %d\n", err);
        return err;
    }

    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);
    err = is_pkt_ok(pkt, buf->total_size, netif);
    if (err != NET_ERR_OK)
    {
        dbg_WARNING(DBG_IP, "packet is broken");
        return err;
    }

    iphdr_ntohs(pkt);
    // 当ip数据包总体不足46字节时，会在包的后面补充一些字节让它到达46
    // 在对数据包进行处理前，需要把后面的一些字节移除
    err = pktbuf_resize(buf, pkt->hdr.total_len);

    // 判断一下目的ip是不是发给我这个网卡的，或者发的广播包我们也处理
    ipaddr_t dest_ip, src_ip;
    ipaddr_from_buf(&dest_ip, pkt->hdr.dest_ip);
    ipaddr_from_buf(&src_ip, pkt->hdr.src_ip);
    if (!ipaddr_is_match(&netif->ipaddr, &netif->netmask, &dest_ip))
    {
        dbg_WARNING(DBG_IP, "ipaddr not match");
        return NET_ERR_UNREACH;
    }

    if (pkt->hdr.frag_offset || pkt->hdr.more)
        err = ip_frag_in(netif, buf, &src_ip, &dest_ip);
    else
        err = ip_normal_in(netif, buf, &src_ip, &dest_ip);
    
    return NET_ERR_OK;
}

net_err_t ip_frag_out (uint8_t protocol, ipaddr_t * dest, ipaddr_t * src, pktbuf_t * buf, netif_t * netif)
{
    dbg_info(DBG_IP, "frag send an ip pkt");

    int offset = 0;
    int total = buf->total_size;
    pktbuf_reset_acc(buf);
    while (total)
    {
        int curr_size = buf->total_size;
        if (curr_size + sizeof(ipv4_hdr_t) > netif->mtu)
            curr_size = netif->mtu - sizeof(ipv4_hdr_t);
        
        pktbuf_t* dest_buf = pktbuf_alloc(curr_size + sizeof(ipv4_hdr_t));
        if (!dest_buf)
        {
            dbg_ERROR(DBG_IP, "alloc buffer for frag send failed");
            return NET_ERR_NONE;
        }

        ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(dest_buf);
        pkt->hdr.shdr_all = 0;
        pkt->hdr.version = NET_VERSION_IPV4;
        ipv4_set_hdr_size(pkt, sizeof(ipv4_hdr_t));
        pkt->hdr.total_len = dest_buf->total_size;
        pkt->hdr.id = packet_id;
        pkt->hdr.frag_all = 0;
        pkt->hdr.ttl = NET_IP_DEFAULT_TTL;
        pkt->hdr.protocol = protocol;
        pkt->hdr.hdr_checksum = 0;
        ipaddr_to_buf(src, pkt->hdr.src_ip);
        ipaddr_to_buf(dest, pkt->hdr.dest_ip);
        
        pkt->hdr.frag_offset = offset >> 3;
        pkt->hdr.more = total > curr_size;

        pktbuf_seek(dest_buf, sizeof(ipv4_hdr_t));
        net_err_t err = pktbuf_copy(dest_buf, buf, curr_size);
        if (err < 0)
        {
            dbg_ERROR(DBG_IP, "frag copy failed");
            pktbuf_free(dest_buf);
            return err;
        }

        pktbuf_remove_header(buf, curr_size);
        pktbuf_reset_acc(buf);

        // 填充完成
        iphdr_htons(pkt);
        pktbuf_reset_acc(dest_buf);
        pkt->hdr.hdr_checksum = pktbuf_checksum16(dest_buf, ipv4_hdr_size(pkt), 0, 1);

        display_ip_pkt(pkt);

        err = netif_out(netif, dest, dest_buf);
        if (err < 0)
        {
            dbg_WARNING(DBG_IP, "send ip packet");
            pktbuf_free(dest_buf);
            return err;
        }

        total -= curr_size;
        offset += curr_size;
    }
    

    packet_id++;
    pktbuf_free(buf);
    return NET_ERR_OK;
    
}

/**
 * 把一个上层协议的包用ip封装好，然后发出去
 * @param protocol 上层协议
 * @param dest 目的地之
 * @param src 源地址
 * @param buf 待发送的数据包(还没添加ip包头)
 * @return net_err错误类型
 */
net_err_t ipv4_out(uint8_t protocol, ipaddr_t* dest, ipaddr_t* src, pktbuf_t* buf)
{
    dbg_info(DBG_IP, "send an ip pkt");
    
    
    rentry_t* rt = rt_find(dest);
    if (!rt)
    {
        dbg_error(DBG_IP, "can not find route table.");
        return NET_ERR_UNREACH;
    }

    ipaddr_t next_hop;
    if (ipaddr_is_any(&rt->next_hop))
        ipaddr_copy(&next_hop, dest);
    else
        ipaddr_copy(&next_hop, &rt->next_hop);

    netif_t* netif = netif_get_default();
    if (netif->mtu && ((buf->total_size + sizeof(ipv4_hdr_t)) > netif->mtu))
    {
        net_err_t err = ip_frag_out(protocol, dest, src, buf, netif);
        if (err < 0)
        {
            dbg_WARNING(DBG_IP, "send ip frag failed.");
            return err;
        }

        return NET_ERR_OK;
    }

    net_err_t err = pktbuf_add_header(buf, sizeof(ipv4_hdr_t), 1);
    if (err < 0)
    {
        dbg_ERROR(DBG_IP, "add header failed");
        return NET_ERR_SIZE;
    }

    ipv4_pkt_t* pkt = (ipv4_pkt_t*)pktbuf_data(buf);

    pkt->hdr.shdr_all = 0;
    pkt->hdr.version = NET_VERSION_IPV4;
    ipv4_set_hdr_size(pkt, sizeof(ipv4_hdr_t));
    pkt->hdr.total_len = buf->total_size;
    pkt->hdr.id = packet_id;
    pkt->hdr.frag_all = 0;
    pkt->hdr.ttl = NET_IP_DEFAULT_TTL;
    pkt->hdr.protocol = protocol;
    pkt->hdr.hdr_checksum = 0;
    if (!src || ipaddr_is_any(src))
        ipaddr_to_buf(&netif->ipaddr, pkt->hdr.src_ip);
    else
        ipaddr_to_buf(src, pkt->hdr.src_ip);
    ipaddr_to_buf(dest, pkt->hdr.dest_ip);
    
    // 填充完成
    iphdr_htons(pkt);
    pktbuf_reset_acc(buf);
    pkt->hdr.hdr_checksum = pktbuf_checksum16(buf, ipv4_hdr_size(pkt), 0, 1);
    display_ip_pkt(pkt);

    err = netif_out(netif_get_default(), &next_hop, buf);
    if (err < 0)
    {
        dbg_WARNING(DBG_IP, "send ip packet");
        return err;
    }
    return NET_ERR_OK;
}