
#ifndef __MEMCACHE_H__
#define __MEMCACHE_H__


struct fourtuple;

struct historical_result
{
    unsigned int succ;
    unsigned int fail1;
    unsigned int fail2;
};

void set_sid(struct fourtuple *f, int sid);
int get_sid(struct fourtuple *f);

void set_ttl(unsigned int daddr, unsigned char ttl);
void set_ttl_if_lt(unsigned int daddr, unsigned char ttl);
unsigned char get_ttl(unsigned int daddr);
void incr_ttl(unsigned int daddr);
void decr_ttl(unsigned int daddr);

void incr_succ(unsigned int daddr, int sid);
void incr_fail1(unsigned int daddr, int sid);
void incr_fail2(unsigned int daddr, int sid);
struct historical_result *get_hist_res(unsigned int daddr);

int load_ttl_from_redis();
int save_ttl_to_redis();

void save_historical_result_to_redis();
void load_historical_result_from_redis();

// debug
void conn_info_cache_summary();
void conn_info_cache_dump();
void host_info_cache_summary();
void host_info_cache_dump();

#endif

