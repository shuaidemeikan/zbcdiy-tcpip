#include <stdio.h>
#include "sys_plat.h"
#include "net.h"
#include "netif_pcap.h"
#include "debug.h"
#include "nlist.h"
#include "mblock.h"
#include "pktbuf.h"
#include "netif.h"
#include "ether.h"
#include "tools.h"
#include "timer.h"
#include "arp.h"
#include "ipv4.h"
#include "ping\ping.h"
#include "exmsg.h"

pcap_data_t netdev0_data = {.ip = netdev0_phy_ip, .hwaddr = netdev0_hwaddr};
net_err_t netdev_init()
{
	netif_t* netif = netif_open("netif 0", &netdev_ops, &netdev0_data);
	if (!netif)
	{
		dbg_ERROR(DBG_NETIF, "open netif err");
		return NET_ERR_NONE;
	}

	ipaddr_t ip, mask, gw;
	ipaddr_from_str(&ip, netdev0_ip);
	ipaddr_from_str(&mask, netdev0_mask);
	ipaddr_from_str(&gw, netdev0_gw);
	netif_set_addr(netif, &ip, &mask, &gw);

	netif_set_active(netif);

	pktbuf_t* buf = pktbuf_alloc(32);
	pktbuf_fill(buf, 0x53, 32);
	ipaddr_t dest, src;
	ipaddr_from_str(&dest, friend0_ip);
	ipaddr_from_str(&src, netdev0_ip);

	ipv4_out(0, &dest, &src, buf);
	return NET_ERR_OK;
}

typedef struct _tnode_t
{
	int id;
	nlist_node_t node;
}tnode_t;

void nlist_test(void)
{
	#define NODE_CNT 4
	tnode_t node[NODE_CNT];
	nlist_t list;

	nlist_init(&list);
	plat_printf("link list first add\n");
	for (int i = 0; i < NODE_CNT; i++)
	{
		nlist_insert_first(&list, &(node[i].node));
		node[i].id = i;
	}

	nlist_node_t* p;
	// for (p = (&list)->first; (p) ; (p) = (p)->next)
	nlist_for_each(p, &list)
	{
		// (tnode_t*)((char*)(p) - ((char*)(&(((tnode_t*)0)->node))))
		tnode_t* tnode = nlist_entry(p, tnode_t, node);
		plat_printf("id:%d\n",tnode->id);
	}

	// 测试链表的删除
	plat_printf("link list remvoe test at head\n");
	for (int i = 0; i < NODE_CNT; i++)
	{
		p = nlist_remove_first(&list);
		plat_printf("remove node id is: %d\n", nlist_entry(p, tnode_t, node)->id);
	}

////////////////////////////////////////////////////////////////////////////////////
	plat_printf("link list end add\n");
	for (int i = 0; i < NODE_CNT; i++)
	{
		nlist_insert_last(&list, &(node[i].node));
		node[i].id = i;
	}

	// for (p = (&list)->first; (p) ; (p) = (p)->next)
	nlist_for_each(p, &list)
	{
		// (tnode_t*)((char*)(p) - ((char*)(&(((tnode_t*)0)->node))))
		tnode_t* tnode = nlist_entry(p, tnode_t, node);
		plat_printf("id:%d\n",tnode->id);
	}

	// 测试链表的删除
	plat_printf("link list remvoe test at end\n");
	for (int i = 0; i < NODE_CNT; i++)
	{
		p = nlist_remove_first(&list);
		plat_printf("remove node id is: %d\n", nlist_entry(p, tnode_t, node)->id);
	}
}

void mblock_test()
{
	mblock_t blist;
	static uint8_t buffer[100][10];

	mblock_init(&blist, buffer, 100, 10, NLOCKER_THREAD);
	void * temp[10];
	for (int i = 0; i < 10; i++)
	{
		temp[i] = mblock_alloc(&blist, 0);
		plat_printf("block: %p, free_count: %d\n",temp[i], mblock_free_cnt(&blist));
	}

	for (int i = 0; i < 10; i++)
	{
		mblock_free(&blist, temp[i]);
		plat_printf("free_count: %d\n", mblock_free_cnt(&blist));
	}
}

void ptkbuf_test(void)
{
	pktbuf_t* buf = pktbuf_alloc(2000);
	//pktbuf_free(buf);
	for (int i = 0 ; i < 16; i++)
		pktbuf_add_header(buf, 33, 0);

	for (int i = 0; i < 16; i++)
		pktbuf_remove_header(buf, 33);
	pktbuf_free(buf);

	buf = pktbuf_alloc(8);
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 4922);
	pktbuf_resize(buf, 1921);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 0);
	pktbuf_free(buf);

	buf = pktbuf_alloc(689);
	pktbuf_t * sbuf = pktbuf_alloc(892);
	pktbuf_join(buf, sbuf);
	pktbuf_free(buf);

	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));

	pktbuf_set_cont(buf, 44);
	pktbuf_set_cont(buf, 60);
	pktbuf_set_cont(buf, 44);
	pktbuf_set_cont(buf, 128);
	pktbuf_set_cont(buf, 135);		
	pktbuf_free(buf);

	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));
	pktbuf_join(buf, pktbuf_alloc(512));	
	pktbuf_join(buf, pktbuf_alloc(1000));
	static uint16_t temp[1000];
	for (int i = 0; i <= 1000; i++)
		temp[i] = i;
	pktbuf_write(buf, (uint8_t*)temp, pktbuf_total(buf));

	pktbuf_reset_acc(buf);
	static uint16_t read_temp[1000];
	plat_memset(read_temp, 0, sizeof(read_temp));

	pktbuf_read(buf, (uint8_t*)read_temp, pktbuf_total(buf));
	if (plat_memcmp(temp, read_temp, pktbuf_total(buf)) != 0 )
	{
		plat_printf("not equal");
		return;
	}

	plat_memset(read_temp, 0 ,sizeof(read_temp));
	pktbuf_seek(buf, 18 * 2);
	pktbuf_read(buf, (uint8_t*)read_temp, 56);
	if (plat_memcmp(temp + 18, read_temp, 56) != 0)
	{
		plat_printf("not equal");
		return;
	}

	plat_memset(read_temp, 0 ,sizeof(read_temp));
	pktbuf_seek(buf, 85 * 2);
	pktbuf_read(buf, (uint8_t*)read_temp, 56);
	if (plat_memcmp(temp + 85, read_temp, 56) != 0)
	{
		plat_printf("not equal");
		return;
	}

	pktbuf_t * dest = pktbuf_alloc(1024);
	pktbuf_seek(dest, 600);
	pktbuf_seek(buf, 200);
	pktbuf_copy(dest, buf, 122);

	plat_memset(read_temp, 0, sizeof(read_temp));
	pktbuf_seek(dest, 600);
	pktbuf_read(dest, (uint8_t *)read_temp, 122);
	if (plat_memcmp(temp + 100, read_temp, 122) != 0) {
		plat_printf("not equal");
		return;
	}
	
	pktbuf_reset_acc(dest);
	pktbuf_fill(dest, 54, pktbuf_total(dest));


	pktbuf_free(dest);
	pktbuf_free(buf);

}

void timer0_proc (struct _net_timer_t* timer, void* arg)
{
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count);
}

void timer1_proc (struct _net_timer_t * timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer2_proc (struct _net_timer_t * timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer3_proc (struct _net_timer_t * timer, void * arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer_test(void)
{
	static net_timer_t t0, t1, t2, t3;
	net_timer_add(&t0, "t0", timer0_proc, (void*)0, 200, 0);
	net_timer_add(&t1, "t1", timer1_proc, (void*)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t2, "t2", timer2_proc, (void*)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t3, "t3", timer3_proc, (void*)0, 4000, NET_TIMER_RELOAD);

	net_timer_remove(&t0);

}

void basic_test(void)
{
	//nlist_test();
	//mblock_test();
	//ptkbuf_test();

	//timer_test();
}

int main (void) {
	//dbg_assert(1 == 2, "test");
	tools_init();
	net_init();

	netdev_init();

	net_start();
	
	//udp_echo_client_start(friend0_ip, 1000);
	basic_test();

	ping_t p;
	ping_run(&p, friend0_ip, 4, 64, 1000);

	net_err_t test_func (struct _func_msg_t * msg);
	int arg = 0x1234;
	net_err_t err = exmsg_func_exec(test_func, &arg);

	char cmd[32], param[32];
	while(1)
	{
		plat_printf(">>");
		scanf("%s%s", cmd, param);
		if (strcmp(cmd, "ping") == 0)
			ping_run(&p, param, 4, 1000, 1000);
	}
		

	printf("Hello, world");
	return 0;
}