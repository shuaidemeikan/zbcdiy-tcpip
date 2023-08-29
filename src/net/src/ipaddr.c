#include "ipaddr.h"

/**
 * 将一个ipaddr内的ip设为0
 * @param ip ipaddr结构
 */
void ipaddr_set_any(ipaddr_t* ip)
{
    ip->type = IPADDR_V4;
    ip->q_addr = 0;
}

/**
 * 判断一个地址是否为空
 * @param ip 
 * @return 是否为空
 */
int ipaddr_is_any (const ipaddr_t* ip)
{
    return ip->q_addr == 0;
}

/**
 * 把字符串类型的ip存到ipaddr结构里
 * @param dest 被存的ipaddr结构
 * @param str 字符串类型的ip
 * @return err类型的返回值
 */
net_err_t ipaddr_from_str(ipaddr_t* dest, char * str)
{
    if (!dest || !str)
        return NET_ERR_PARAM;

    uint8_t sub_addr = 0;
    uint8_t* p = dest->a_addr;
    int i = 0;
    char c = str[i];
    while (c != '\0')
    {
        if (c >= '0' && c <= '9')
            sub_addr = sub_addr * 10 + (c - '0');
        else if (c == '.')
        {
            *p++ = sub_addr;
            sub_addr = 0;
        }else
            return NET_ERR_PARAM;
        i++;
        c = str[i];
    }

    *p = sub_addr; 
    return NET_ERR_OK;
}

/**
 * 将一个ipaddr结构内的数据拷贝到另一个ipaddr结构内
 * @param dest 目标ipaddr结构
 * @param src 被拷的ipaddr结构
 */
void ipaddr_copy(ipaddr_t* dest, ipaddr_t* src)
{
    if (!dest || !src)
        return;
    
    dest->q_addr = src->q_addr;
    dest->type = src->type;
}

/**
 * 返回一个ip地址为空的ipaddr结构
 * @return ip地址为空的ipaddr结构
 */
ipaddr_t* ipaddr_get_any(void)
{
    static ipaddr_t ipaddr_any = {.q_addr = 0, .type = IPADDR_V4};
    return &ipaddr_any;
}

int ipaddr_is_equal (ipaddr_t* ipaddr1, ipaddr_t* ipaddr2)
{
    return ipaddr1->q_addr == ipaddr2->q_addr;
}

/**
 * 将一个ipaddr结构内的数据拷贝到一个单纯的地址处
 * @param ipaddr 被拷贝的结构
 * @param target 复制到的目标地址
 */
void ipaddr_to_buf(const ipaddr_t* ipaddr, uint8_t* target)
{
    *(uint32_t*)target = ipaddr->q_addr;
}

void ipaddr_from_buf (ipaddr_t* dest, uint8_t* ip_buf)
{
    dest->type = IPADDR_V4;
    dest->q_addr = *(uint32_t*)ip_buf;
}

int ipaddr_is_local_broadcast (const ipaddr_t* ipaddr)
{
    return ipaddr->q_addr == 0xFFFFFFFF;
}

/**
 * 传入一个ip地址和掩码，获得该ip地址的网络号
 * @param ipaddr 待获取网络号的ip地址
 * @param netmask 子网掩码
 * @return uint32类型的网络号
 */
static inline uint32_t get_network (const ipaddr_t* ipaddr, const ipaddr_t* netmask)
{
    uint32_t ip = ipaddr->q_addr;
    uint32_t netmaskip = netmask->q_addr;
    return netmaskip & ip;
}

int ipaddr_is_direct_broadcast (const ipaddr_t* ipaddr, const ipaddr_t* netmask, const ipaddr_t* targetip)
{
    uint32_t netifip = ipaddr->q_addr;
    uint32_t netmaskip = netmask->q_addr;
    uint32_t target = targetip->q_addr;

    uint32_t netif_network = netmaskip & netifip;
    uint32_t target_network = netmaskip & target;

    if (target_network == netif_network)
    {
        if (targetip->a_addr[3] == 255)
            return 1;
    }
    return 0;
}

int ipaddr_is_match (const ipaddr_t* ipaddr, const ipaddr_t* netmask, const ipaddr_t* targetip)
{
    if (ipaddr_is_direct_broadcast(ipaddr, netmask, targetip))
        return 1;
    
    if (ipaddr_is_local_broadcast(targetip))
        return 1;

    return ipaddr_is_equal((ipaddr_t*)ipaddr, (ipaddr_t*)targetip);
}