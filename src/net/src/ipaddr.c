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