#include "udp_echo_server.h"
#include "sys_plat.h"
#include <stdio.h>
#include <WinSock2.h>
#include "net_api.h"
static uint16_t server_port;

static void udp_echo_server_thread (void *arg)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        printf("opens ocket error\n");
        goto end;
    }

    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(server_port);
    local_addr.sin_addr.s_addr = htons(INADDR_ANY);
    // 绑定本地端口
    // if (bind(s, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0)
    // {
    //     printf("bind error\n");
    //     goto end;
    // }

    while (1)
    {
        struct sockaddr_in client_addr;
        char buf[256];

        socklen_t addr_len = sizeof(client_addr);
        ssize_t size = recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)&client_addr, &addr_len);
        if (size < 0)
        {
            printf("recv from error\n");
            goto end;
        }

        // 由于打印调io比较耗时，所以udp包会因为来不及处理而被丢弃
        plat_printf("udp echo server:connect ip: %s, port: %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
        size = sendto(s, buf, size, 0, (struct sockaddr*)&client_addr, addr_len);
        if (size < 0)
        {
            printf("sendto error\n");
            goto end;
        }
    }
end:
    if (s >= 0)
    {
        closesocket(s);
    }
}

net_err_t udp_echo_server_start (int port)
{
    printf("UDP echo server started on port %d\n", port);
    server_port = port;
    if (sys_thread_create(udp_echo_server_thread, (void*)0) == SYS_THREAD_INVALID)
        return NET_ERR_SYS;

    return NET_ERR_OK;
}