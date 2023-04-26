#include "debug.h"
#include "sys_plat.h"
#include <stdarg.h>

const char* titile[] = 
{
    [DBG_LEVEL_ERROR] = DBG_STYLE_ERROR"error",
    [DBG_LEVEL_WARNING] = DBG_STYLE_WARNING"warning",
    [DBG_LEVEL_INFO] = DBG_STYLE_RESET"info"
};

void dbg_print(int current_level, int target_level, const char* file, const char* func, int line, const char* fmt, ...)
{ 
    //检测log打印的等级是否允许打印
    if (current_level >= target_level)
    {
        //对文件路径进行处理
        const char* end = file + plat_strlen(file);
        while (end > file)
        {
            if (*end == '\\' || *end == '/')
                break;
            else
                end--;
        }
        if (end > file)
            end++;
        // 此时end指向的是最后一个斜杠的末尾
        //plat_printf("%s(%s-%s-%d)",titile[target_level], end, func, line);

        char str_buf[128];
        va_list args;
        va_start(args, fmt);
        plat_vsprintf(str_buf, fmt, args);
        plat_printf("%s(%s-%s-%d):%s\n"DBG_STYLE_RESET, titile[target_level], end, func, line,str_buf);
        va_end(args);
    }
    
}

/**
 * 把一个uint8_t*类型的硬件地址打印出来
 * @param msg 打印前要显示的字符
 * @param hwaddr 要打印的硬件地址
 * @param len 要打印的硬件地址的长度
 * @return err类型的返回值
 */
void dbg_dump_hwaddr (const char* msg, const uint8_t* hwaddr, int len)
{
    if (msg)
        plat_printf("%s:", msg);

    // %02x表示从内存中取出两位16进制数打印出来
    if (len)
    {
        for (int i = 0; i < len; i++)
            plat_printf("%02x-", hwaddr[i]);
    }else
        plat_printf("none");
    
}

/**
 * 打印一个ipaddr结构内存储的ip地址
 * @param msg 打印前要显示的字符串
 * @param ipaddr 要打印的ipaddr结构
 */
void dbg_dump_ip (const char* msg, const ipaddr_t* ipaddr)
{
    if (msg)
        plat_printf("%s:", msg);
    
    if (ipaddr)
        plat_printf("%d.%d.%d.%d", ipaddr->a_addr[0],ipaddr->a_addr[1],ipaddr->a_addr[2],ipaddr->a_addr[3]);
    else
        plat_printf("0.0.0.0");
}