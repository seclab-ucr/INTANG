
#ifndef __MYCACHE_H__
#define __MYCACHE_H__

#include <time.h>

#define DEFAULT_VALIDITY_PERIOD 90
#define RST_VALIDITY_PERIOD 90
#define HTTPREQ_VALIDITY_PERIOD 5
#define HASH_TBL_SIZE 65535

#define MAX_REQLINE_LEN 200

#define ENTRY_FOUND     1
#define ENTRY_NOT_FOUND 0

#define ENTRY_NOT_EXIST 1
#define ENTRY_EXISTS    2


/*
 * Array cache
 */

struct cache_entry {
    unsigned int key;
    void *value;
    time_t ts;
};

struct array_cache {
    unsigned int size;
    struct cache_entry *cache;
    unsigned int idx;
    int validity;
};


int array_cache_set(struct array_cache *ac, unsigned int key, void *value);
void *array_cache_get(struct array_cache *ac, unsigned int key);
void array_cache_summary(struct array_cache *ac);
void array_cache_dump(struct array_cache *ac);


/*
 * Hash table cache (deprecated)
 */

struct fourtuple;

struct inode {
    struct fourtuple *key;
    int value;
    time_t ts;
    struct inode *next;
};

struct snode {
    struct fourtuple *key;
    char *value;
    time_t ts;
    struct snode *next;
};

struct inode* rst_hashtbl[HASH_TBL_SIZE];
struct snode* httpreq_hashtbl[HASH_TBL_SIZE];

int icache_get(struct fourtuple *key, int *value);
int icache_set(struct fourtuple *key, int value);
int icache_clear(struct fourtuple *key);

int scache_get(struct fourtuple *key, char **value);
int scache_set(struct fourtuple *key, char *value);
int scache_clear(struct fourtuple *key);

// Debug functions
void dump_icache();
void summary_icache();
void dump_scache();
void summary_scache();

int init_cache();

/*
 * RST cache
 */ 
void rst_cache_init();
int get_rst_count(struct fourtuple *fourtp);
int set_rst_count(struct fourtuple *fourtp, int cnt);
/*
 * HTTP cache
 */ 
void http_cache_init();
char* get_last_http_request(struct fourtuple *fourtp);
int set_last_http_request(struct fourtuple *fourtp, char *httpreq);
/*
 * DNS cache
 */ 
void dns_cache_init();
struct fourtuple* dns_cache_get(unsigned int key);
int dns_cache_set(unsigned int key, struct fourtuple *fourtp);


#endif

