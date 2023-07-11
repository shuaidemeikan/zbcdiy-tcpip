#include "tools.h"
#include "debug.h"

static int is_litte_endian(void)
{
    uint16_t test = 0x1234;
    if (*(uint8_t*)(&test) == 0x34)
        return 1;
    else
        return 0;
}

net_err_t tools_init (void)
{
    dbg_info(DBG_TOOLS, "init tools");

    if (is_litte_endian() != NET_ENDIAN_LITTLE)
    {
        dbg_ERROR(DBG_TOOLS, "check endian failed");
        return NET_ERR_SYS;
    }

    dbg_info(DBG_TOOLS, "init tools");
    return NET_ERR_OK;
}