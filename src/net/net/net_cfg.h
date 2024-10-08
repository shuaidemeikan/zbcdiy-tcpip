#ifndef NET_CFG_H
#define NET_CFG_H

#define dbg_error   dbg_ERROR
#define dbg_warning dbg_WARNING

#define DBG_MBLOCK      DBG_LEVEL_ERROR
#define DGB_QUEUE       DBG_LEVEL_ERROR
#define DBG_MSG         DBG_LEVEL_ERROR
#define DBG_BUF         DBG_LEVEL_ERROR
#define DBG_INIT        DBG_LEVEL_ERROR
#define DBG_PLAT        DBG_LEVEL_ERROR
#define DBG_NETIF       DBG_LEVEL_ERROR
#define DBG_ETHER       DBG_LEVEL_ERROR
#define DBG_TOOLS       DBG_LEVEL_ERROR
#define DBG_TIMER       DBG_LEVEL_ERROR
#define DBG_ARP         DBG_LEVEL_ERROR
#define DBG_IP          DBG_LEVEL_INFO
#define DBG_ICMPv4      DBG_LEVEL_ERROR
#define DBG_SOCKET      DBG_LEVEL_ERROR
#define DBG_RAW         DBG_LEVEL_ERROR
#define DBG_UDP         DBG_LEVEL_ERROR
#define DBG_TCP         DBG_LEVEL_INFO

#define NET_ENDIAN_LITTLE           1

#define NET_ENDIAN_LITTLE   1

#define EXMSG_MSG_CNT   10

#define EXMSG_LOCKER    NLOCKER_THREAD

#define PKTBUF_BLK_SIZE     128
#define PKTBUF_BUF_CNT      150
#define PKTBUF_BLK_CNT      150

#define NETIF_HWADDR_SIZE   10
#define NETIF_NAME_SIZE     10
#define NETIF_INQ_SIZE      50
#define NETIF_OUTQ_SIZE     50
#define NETIF_DEV_CNT       10

#define TIMER_NAME_SIZE     30

#define ARP_CACHE_SIZE      50
#define ARP_MAX_PKT_WAIT    5
#define ARP_TIMER_TMO           1
#define ARP_ENTRY_STABLE_TMO    5
#define ARP_ENTRY_PENDING_TMO   3
#define ARP_ENTRY_RETRY_CNT     5

#define IP_FRAGS_MAX_NR         5
#define IP_FRAG_MAX_BUF_NR      20
#define IP_FRAG_SCAN_PERIOD     1
#define IP_FRAG_TMO             10

#define IP_RTTABLE_SIZE         10

#define RAW_MAX_RECV           50

#define UDP_MAX_NR              4
#define UDP_MAX_RECV            50
#define NET_PORT_DYN_START      1024
#define NET_PORT_DYN_END        65535

#define TCP_MAX_NR              30
#define TCP_SBUF_SIZE           2048
#define TCP_RBUF_SIZE           2048
#endif // !NET_CFG_H