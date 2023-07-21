#ifndef DEBUG_H
#define DEBUG_H

#include "net_cfg.h"
#include "ipaddr.h"

#define DBG_STYLE_ERROR     "\033[31m"
#define DBG_STYLE_WARNING     "\033[33m"
#define DBG_STYLE_RESET     "\033[0m"

#define DBG_LEVEL_NONE         0
#define DBG_LEVEL_ERROR        1
#define DBG_LEVEL_WARNING      2
#define DBG_LEVEL_INFO         3


void dbg_print(int current_level, int target_level, const char* file, const char* func, int line, const char* fmt, ...);
void dbg_dump_hwaddr (const char* msg, const uint8_t* hwaddr, int len);
void dbg_dump_ip (const char* msg, const ipaddr_t* ipaddr);
void dbg_dump_ip_buf (const char* msg, const uint8_t* ipaddr);
#define dbg_info(target_level, fmt, ...) dbg_print(DBG_LEVEL_INFO, target_level, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define dbg_WARNING(target_level, fmt, ...) dbg_print(DBG_LEVEL_WARNING, target_level, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define dbg_ERROR(target_level, fmt, ...) dbg_print(DBG_LEVEL_ERROR, target_level, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#define dbg_assert(expr, mess)  {\
    if (!(expr)){\
        dbg_print(DBG_LEVEL_ERROR, DBG_LEVEL_ERROR, __FILE__, __FUNCTION__, __LINE__, "assert faild:"#expr","mess); \
    while(1){} \
    }\
}

#define DBG_DISP_ENABLED(module)     (module >= DBG_LEVEL_INFO)
#endif