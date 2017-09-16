
#ifndef __DNSCLI_H__
#define __DNSCLI_H__

struct fourtuple;

int init_dns_cli();
int send_dns_req(const unsigned char *dns_req, size_t len);
int fabricate_dns_udp_response(struct fourtuple *fourtp, const char *dns_req, unsigned short len);


#endif

