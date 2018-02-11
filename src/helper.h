
#ifndef __HELPER_H__
#define __HELPER_H__

#include <unistd.h>
#include <sys/types.h>
#include <string.h>


#define TIME_START { clock_gettime(CLOCK_REALTIME, &ts); t1 = ts.tv_sec + ts.tv_nsec / 1000000000.0; }

#define TIME_END { clock_gettime(CLOCK_REALTIME, &ts); t2 = ts.tv_sec + ts.tv_nsec / 1000000000.0; log_debug("Time elasped: %lf", t2 - t1); }


struct send_tcp_vars;
struct mypacket;
struct fourtuple;

// helpers 
int read_version();
void write_version(int version);

void hex_dump(const unsigned char *packet, size_t size);
void human_dump(const unsigned char *packet, size_t size);
void dump_send_tcp_vars(struct send_tcp_vars *vars);
char* tcp_flags(u_int8_t flags);

char* ip2str(u_int32_t ip, char *str);
u_int32_t str2ip(const char *str);

void show_packet(struct mypacket *packet);

unsigned int make_hash(struct fourtuple *f);
unsigned int make_hash2(unsigned int saddr, unsigned short sport, unsigned int daddr, unsigned short dport);

unsigned int calc_checksum(const unsigned char *payload, unsigned short payload_len);
int choose_appropriate_ttl(int ttl);

int is_ip_in_whitelist(u_int32_t ip);

int is_blocked_ip(const char *ip);

int startswith(const char *a, const char *b);

int is_https_client_hello(const char *payload);
int is_https_server_hello(const char *payload);

#endif

