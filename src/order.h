
#ifndef __ORDER_H__
#define __ORDER_H__

#define ORDER_CACHE_DNS_UDP_REQUEST 1
#define ORDER_CACHE_DNS_TCP_REQUEST 2
#define ORDER_PROC_DNS_UDP_RESPONSE 3
#define ORDER_PROC_DNS_TCP_RESPONSE 4
#define ORDER_CACHE_HTTP_REQUEST    5
#define ORDER_PROC_HTTP_RESPONSE    6
#define ORDER_PROC_INCOMING_RST     7
#define ORDER_CACHE_STRATEGY        8
#define ORDER_NEED_EVAL             9
#define ORDER_REMOVE_VFLAG          10


void order(int type, void *data);

int get_order(void *data);


#endif

