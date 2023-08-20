#include "net_api.h"

#define IPV4_STR_ADDR_SIZE      16  // 四个三位数+三个点+字符串结尾的\0

/**
 * 把一个in_addr类型的地址转换成字符串地址返回
 * @param in in_addr类型的地址
 * @return 转换成的字符串
 */
char* x_inet_ntoa (struct x_in_addr in)
{
    static char buf[IPV4_STR_ADDR_SIZE];
    plat_sprintf(buf, "%d.%d.%d.%d", in.addr0, in.addr1, in.addr2, in.addr3);
    return buf;
}

/**
 * 把一个字符串类型的地址转换成32位地址返回
 * @param str 字符串类型的地址
 * @return 转换成的32位数据
 */
uint32_t x_inet_addr (const char* str)
{
    if (!str)
        return INADDR_ANY;
    
    ipaddr_t ipaddr;
    ipaddr_from_str(&ipaddr, str);
    return ipaddr.q_addr;
}

/**
 * 把一个字符串类型的地址转换成in_addr类型
 * @param family 协议类型，只支持ipv4
 * @param strptr 字符串类型的地址
 * @param addrptr in_addr类型的地址，转换直接修改这里面的值
 * @return 转换是否成功，返回0则成功，小于0则失败
 */
int x_inet_pton (int family, const char* strptr, void* addrptr)
{
    if ((family != AF_INET) || !strptr || !addrptr)
        return -1;
    struct x_in_addr* addr = (struct x_in_addr*)addrptr;

    ipaddr_t ipaddr;
    ipaddr_from_str(&ipaddr, strptr);
    addr->s_addr = ipaddr.q_addr;
    return 0;
}

/**
 * 把一个in_addr类型的地址转换成字符串类型的地址
 * @param family 协议类型，只支持ipv4
 * @param addrptr in_addr类型的地址
 * @param strptr 字符串类型的地址
 * @param len 字符串地址的长度
 * @return 转换后的字符串类型的地址
 */
const char* x_inet_ntop (int family, const void* addrptr, char* strptr, size_t len)
{
    if ((family != AF_INET) || !strptr || !addrptr || !len)
        return (const char*)0;
    
    struct x_in_addr* addr = (struct x_in_addr*)addrptr;
    char buf[IPV4_ADDR_SIZE];
    plat_sprintf(buf, "%d.%d.%d.%d", addr->addr0, addr->addr1, addr->addr2, addr->addr3);
    plat_strncpy(strptr, buf, len-1);
    strptr[len - 1] = '\0';
    return strptr;
}