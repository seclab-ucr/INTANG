
#ifndef __TTL_PROBING_H__
#define __TTL_PROBING_H__


struct mypacket;


void send_probing_SYNs(const char *src_ip, const char *dst_ip, unsigned short dst_port);
int process_synack_for_ttl_probing(struct mypacket *packet);

unsigned char get_ttl(unsigned int daddr);
void set_ttl(unsigned int daddr, unsigned char ttl);

int load_ttl_from_file(char *filename);


#endif

