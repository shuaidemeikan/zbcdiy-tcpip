#include <stdio.h>
#include <string.h>
#include "net_plat.h"
#include <WinSock2.h>

void download_test (const char* filename, int port)
{
    printf("download_test\n");

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
    {
        printf("create socket failed.\n");
        return;
    }

    FILE* file = fopen(filename, "wb");
    if (file == (FILE*)0)
    {
        printf("open file failed.\n");
        goto end;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(friend0_ip);
    server_addr.sin_port = htons(port);

    if (connect(sockfd, (const struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("connect failed.\n");
        goto end;
    }

    ssize_t total_size = 0;
    char buf[8192];
    int rcv_size;
    while ((rcv_size = recv(sockfd, buf, sizeof(buf), 0)) > 0)
    {
        fwrite(buf, 1, rcv_size, file);
        fflush(file);
        printf(".");
        total_size += rcv_size;
    }

    if (rcv_size < 0)
    {
        printf("rcv file size: %d\n", (int)total_size);
        goto end;
    }

    printf("rcv file size: %d\n", (int)total_size);
    printf("rcv file ok\n");
    closesocket(sockfd);
    fclose(file);
    return;

end:
    printf("down error end\n");
    closesocket(sockfd);
    if (file)
        fclose(file);
    return;
}