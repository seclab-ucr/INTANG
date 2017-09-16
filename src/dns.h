
#ifndef __DNS_H__
#define __DNS_H__


struct mypacket;

int dns_strat_process(struct mypacket *packet);

int is_poisoned_domain(const char *domain);

int init_dns_tcp_conn();

int dns_proxy_loop();

#endif

