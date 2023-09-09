#include "ping.h"
#include <WinSock2.h>
#include "sys_plat.h"
#include "net_api.h"

uint16_t checksum (void * buf, uint16_t len) 
{
    uint16_t * curr_buf = (uint16_t *)buf;
    uint32_t checksum = 0;

    while (len > 1) {
        checksum += *curr_buf++;
        len -= 2;
    }

    if (len > 0) {
        checksum += *(uint8_t *)curr_buf;
    }

    uint16_t high;
    while ((high = checksum >> 16) !=0) {
        checksum = high + (checksum & 0xFFFF);
    }
    
    return(uint16_t)~checksum;
}

void ping_run (ping_t* ping, const char* dest, int count, int size, int interval)
{
    static start_id = PING_DEFAULT_ID;                          // 给ping包加入一个id
    // windows套接字编程初始化
    WSADATA wsdata;                                             
    WSAStartup(MAKEWORD(2, 2), &wsdata);
    int s = x_socket(AF_INET, SOCK_RAW, IPPROTP_ICMP);       // 获得一个套接字
    if (s < 0)
    {
        plat_printf("ping: open socket error");
        return;
    }

    //int tmo = 3000;                                             // 设置套接字收包的超时时间
    //setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));     // 设置套接字属性

    struct timeval tmo;
    tmo.tv_sec = 0;
    tmo.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tmo, sizeof(tmo));

    // 拿到并设置一个ipv4地址结构
    struct sockaddr_in addr;
    plat_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(dest);
    addr.sin_port = 0;

    //connect(s, (const struct sockaddr*)&addr, sizeof(addr));

    int fill_size = size > PING_BUFFER_SIZE ? PING_BUFFER_SIZE : size;      // 设置ip包载荷最大大小
    // 填充载荷
    for (int i = 0; i < fill_size; i++)
        ping->req.buf[i] = i;

    int total_size = sizeof(icmp_hdr_t) + fill_size;        // 获得ip包整体大小(包头+载荷)
    // 填充ip包的数据结构
    for (int i = 0, seq = 0; i < count; i++, seq++)
    {
        ping->req.echo_hdr.type = 8;
        ping->req.echo_hdr.code = 0;
        ping->req.echo_hdr.checksum16 = 0;
        ping->req.echo_hdr.id = start_id;
        ping->req.echo_hdr.seq = seq;
        ping->req.echo_hdr.checksum16 = checksum(&ping->req, total_size);

        int size = sendto(s, (const char*)&ping->req, total_size, 0, (const struct sockaddr*)&addr, sizeof(addr));
        //int size = send(s, (const char*)&ping->req, total_size, 0);     // 把包发出去
        // 上面的函数会返回发出去包的大小，如果大小小于0，说明发送失败了
        if (size < 0)
        {
            plat_printf("send pig request failed.");
            break;
        }

        clock_t time = clock();

        memset(&ping->reply, 0, sizeof(ping->reply));

        do
        {
            struct sockaddr_in from_addr;
            int addr_len = sizeof(addr);
            size = recvfrom(s, (char*)&ping->reply, sizeof(ping->reply), 0, (struct sockaddr*)&from_addr, &addr_len);
            // 接收回包
            //size = recv(s, (char*)&ping->reply, sizeof(ping->reply), 0);
            if (size < 0)
            {
                plat_printf("ping recv tmo\n");
                break;
            }

            if ((ping->req.echo_hdr.id == ping->reply.echo_hdr.id) && (ping->req.echo_hdr.seq == ping->reply.echo_hdr.seq))
                break;
        } while (1);
        
        // 判断一下收到的回包的合法性
        int recv_size = size - sizeof(ip_hdr_t) - sizeof(icmp_hdr_t);
        if (memcmp(ping->req.buf, ping->reply.buf, recv_size))
        {
            plat_printf("recv data error\n");
            continue;
        }

        ip_hdr_t* iphdr = &ping->reply.iphdr;
        int send_size = fill_size;
        if (recv_size == send_size)
            plat_printf("reply from %s: bytes=%d, ", inet_ntoa(addr.sin_addr), send_size);
        else
            plat_printf("reply from %s: bytes=%d(send=%d) , ", inet_ntoa(addr.sin_addr), recv_size, send_size);
        
        int diff_ms = (clock() - time) / (CLOCKS_PER_SEC / 1000);

        if (diff_ms < 1)
            plat_printf("time < 1ms, TTL=%d\n", iphdr->ttl);
        else
            plat_printf("time = %dms, TTL=%d\n", diff_ms, iphdr->ttl);
        
        sys_sleep(interval);

    }

    close(s);

    //closesocket(s);
}

