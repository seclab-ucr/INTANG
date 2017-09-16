
/*
 * Cache with validity period
 * There're two kinds of cache. One is implemented with hash table,
 * and the other is with array.
 */

#include "mycache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "helper.h"
#include "protocol.h"
#include "logging.h"


static inline int is_expired(time_t ts)
{
    return ts + DEFAULT_VALIDITY_PERIOD < time(NULL);
}

/*
 * Array cache
 */

void array_cache_init(struct array_cache *ac, unsigned int size, int validity)
{
    ac->size = size;
    ac->cache = (struct cache_entry*)malloc(sizeof(struct cache_entry) * size);
    ac->idx = 0;
    ac->validity = validity;
}

// put the data into the oldest slot.
int array_cache_set(struct array_cache *ac, unsigned int key, void *value)
{
    time_t now = time(NULL);
    unsigned int i;
    if (ac->cache[ac->idx].ts + ac->validity < now) {
        if (ac->cache[ac->idx].value != NULL) {
            free(ac->cache[ac->idx].value);
        }
        ac->cache[ac->idx].key = key;
        ac->cache[ac->idx].value = value;
        ac->cache[ac->idx].ts = now;
        ac->idx = (ac->idx + 1) % ac->size;
    }
    else {
        log_error("CACHE IS FULL!!!");
        return -1;
    }
    return 0;
}

// get the most recent data with the key
void *array_cache_get(struct array_cache *ac, unsigned int key)
{
    time_t now = time(NULL);
    unsigned int i = (ac->idx - 1) % ac->size;
    while (i != ac->idx) {
        if (ac->cache[i].ts + ac->validity < now)
            break;
        if (ac->cache[i].key == key) {
            return ac->cache[i].value;
        }
        i = (i - 1) % ac->size;
    }
    log_debug("array_cache_get: key not found!");
    return NULL;
}


void array_cache_summary(struct array_cache *ac)
{
    time_t now = time(NULL);
    unsigned int valid_num = 0;
    unsigned int i = (ac->idx - 1) % ac->size;
    while (i != ac->idx) {
        if (ac->cache[i].ts + ac->validity < now) {
            break;
        }
        valid_num++;
    }
    printf("Idx: %u\n", ac->idx);
    printf("Utilization rate: %u/%u(%f)\n", valid_num, ac->size, ((float)valid_num)/ac->size);
    printf("Validity period: %d\n", ac->validity);
}

void array_cache_dump(struct array_cache *ac)
{
    unsigned int i;
    for (i = 0; i < ac->size; i++) {
        printf("%d. %u\t%p\t%s", i, ac->cache[i].key, ac->cache[i].value, ctime(&ac->cache[i].ts));
    }
}


/*
 * Hash table cache (deprecated)
 */

int icache_get(struct fourtuple *key, int *value)
{
    //log_debug("%u, %u, %u, %u", key->sip, key->dip, key->sport, key->dport);
    unsigned int hash_val = make_hash(key);
    unsigned int index = hash_val % HASH_TBL_SIZE;
    //log_debug("index: %d", index);
    if (rst_hashtbl[index]) {
        struct inode *cur, *last = NULL;
        for (cur = rst_hashtbl[index]; cur != NULL; cur = cur->next) {
            if (cur->key->sip == key->sip &&
                    cur->key->dip == key->dip &&
                    cur->key->sport == key->sport &&
                    cur->key->dport == key->dport) {
                if (cur->ts + RST_VALIDITY_PERIOD < time(NULL)) {
                    // expired
                    log_debug("Cache expired.");
                    if (last == NULL) 
                        rst_hashtbl[index] = NULL;
                    else
                        last->next = cur->next;
                    free(cur->key);
                    free(cur);
                    return ENTRY_NOT_FOUND;
                }
                *value = cur->value;
                return ENTRY_FOUND;
            }
            last = cur;
        }
    }
    return ENTRY_NOT_FOUND;
}

int icache_set(struct fourtuple *key, int value)
{
    unsigned int hash_val = make_hash(key);
    unsigned int index = hash_val % HASH_TBL_SIZE;
    if (rst_hashtbl[index]) {
        struct inode *cur, *last;
        for (cur = rst_hashtbl[index]; cur != NULL; cur = cur->next) {
            if (cur->key->sip == key->sip &&
                    cur->key->dip == key->dip &&
                    cur->key->sport == key->sport &&
                    cur->key->dport == key->dport) {
                cur->value = value;
                cur->ts = time(NULL);
                printf("set value to %d\n", value);
                return ENTRY_EXISTS;
            }
            last = cur;
        }
        // append to the linked list, don't need to consider the order for now
        struct inode *new_node = (struct inode*)malloc(sizeof(struct inode));
        new_node->key->sip = key->sip;
        new_node->key->dip = key->dip;
        new_node->key->sport = key->sport;
        new_node->key->dport = key->dport;
        new_node->value = value;
        new_node->ts = time(NULL);
        new_node->next = NULL;
        last->next = new_node;
        printf("inserted a new node\n");
        return ENTRY_NOT_EXIST;
    } 
    // not found, create one
    struct inode *new_node = (struct inode*)malloc(sizeof(struct inode));
    struct fourtuple *new_key = (struct fourtuple*)malloc(sizeof(struct fourtuple));
    new_key->sip = key->sip;
    new_key->dip = key->dip;
    new_key->sport = key->sport;
    new_key->dport = key->dport;
    new_node->key = new_key;
    new_node->value = value;
    new_node->ts = time(NULL);
    new_node->next = NULL;
    rst_hashtbl[index] = new_node;
    printf("inserted a new node\n");
    return ENTRY_NOT_EXIST;
}

int icache_clear(struct fourtuple *key)
{
    unsigned int hash_val = make_hash(key);
    unsigned int index = hash_val % HASH_TBL_SIZE;
    if (rst_hashtbl[index]) {
        struct inode *cur, *last = NULL;
        for (cur = rst_hashtbl[index]; cur != NULL; cur = cur->next) {
            if (cur->key->sip == key->sip &&
                    cur->key->dip == key->dip &&
                    cur->key->sport == key->sport &&
                    cur->key->dport == key->dport) {
                if (last == NULL) 
                    rst_hashtbl[index] = NULL;
                else
                    last->next = cur->next;
                free(cur->key);
                free(cur);
                return ENTRY_FOUND;
            }
            last = cur;
        }
    }
    return ENTRY_NOT_FOUND;
}


// An awful copy from icache, should have a better way to manage string cache in memeory
int scache_get(struct fourtuple *key, char **value)
{
    unsigned int hash_val = make_hash(key);
    unsigned int index = hash_val % HASH_TBL_SIZE;
    if (httpreq_hashtbl[index]) {
        struct snode *cur, *last = NULL;
        for (cur = httpreq_hashtbl[index]; cur != NULL; cur = cur->next) {
            if (cur->key->sip == key->sip &&
                    cur->key->dip == key->dip &&
                    cur->key->sport == key->sport &&
                    cur->key->dport == key->dport) {
                if (cur->ts + HTTPREQ_VALIDITY_PERIOD < time(NULL)) {
                    // expired
                    if (last == NULL) 
                        httpreq_hashtbl[index] = NULL;
                    else
                        last->next = cur->next;
                    free(cur->value);
                    free(cur->key);
                    free(cur);
                    return ENTRY_NOT_FOUND;
                }
                *value = cur->value;
                return ENTRY_FOUND;
            }
            last = cur;
        }
    }
    return ENTRY_NOT_FOUND;
}

int scache_set(struct fourtuple *key, char *value)
{
    unsigned int hash_val = make_hash(key);
    unsigned int index = hash_val % HASH_TBL_SIZE;
    if (httpreq_hashtbl[index]) {
        struct snode *cur, *last;
        for (cur = httpreq_hashtbl[index]; cur != NULL; cur = cur->next) {
            if (cur->key->sip == key->sip &&
                    cur->key->dip == key->dip &&
                    cur->key->sport == key->sport &&
                    cur->key->dport == key->dport) {
                cur->value[0] = 0;
                strncat(cur->value, value, MAX_REQLINE_LEN);
                cur->ts = time(NULL);
                printf("set value to %s\n", value);
                return ENTRY_EXISTS;
            }
            last = cur;
        }
        // append to the linked list, don't need to consider the order for now
        struct snode *new_node = (struct snode*)malloc(sizeof(struct snode));
        struct fourtuple *new_key = (struct fourtuple*)malloc(sizeof(struct fourtuple));
        char *new_value = (char*)malloc(MAX_REQLINE_LEN+1);
        new_key->sip = key->sip;
        new_key->dip = key->dip;
        new_key->sport = key->sport;
        new_key->dport = key->dport;
        new_value[0] = 0;
        strncat(new_value, value, MAX_REQLINE_LEN);
        new_node->key = new_key;
        new_node->value = new_value;
        new_node->ts = time(NULL);
        new_node->next = NULL;
        last->next = new_node;
        printf("inserted a new node\n");
        return ENTRY_NOT_EXIST;
    } 
    // not found, create one
    struct snode *new_node = (struct snode*)malloc(sizeof(struct snode));
    struct fourtuple *new_key = (struct fourtuple*)malloc(sizeof(struct fourtuple));
    char *new_value = (char*)malloc(MAX_REQLINE_LEN+1);
    new_key->sip = key->sip;
    new_key->dip = key->dip;
    new_key->sport = key->sport;
    new_key->dport = key->dport;
    new_value[0] = 0;
    strncat(new_value, value, MAX_REQLINE_LEN);
    new_node->key = new_key;
    new_node->value = new_value;
    new_node->ts = time(NULL);
    new_node->next = NULL;
    httpreq_hashtbl[index] = new_node;
    printf("inserted a new node\n");
    return ENTRY_NOT_EXIST;
}

int scache_clear(struct fourtuple *key)
{
    unsigned int hash_val = make_hash(key);
    unsigned int index = hash_val % HASH_TBL_SIZE;
    if (httpreq_hashtbl[index]) {
        struct snode *cur, *last = NULL;
        for (cur = httpreq_hashtbl[index]; cur != NULL; cur = cur->next) {
            if (cur->key->sip == key->sip &&
                    cur->key->dip == key->dip &&
                    cur->key->sport == key->sport &&
                    cur->key->dport == key->dport) {
                if (last == NULL) 
                    httpreq_hashtbl[index] = NULL;
                else
                    last->next = cur->next;
                free(cur->key);
                free(cur->value);
                free(cur);
                return ENTRY_FOUND;
            }
            last = cur;
        }
    }
    return ENTRY_NOT_FOUND;
}

// Debug functions

void dump_icache()
{
    int i;
    char buffer[64];
    printf("---------------------------------------------------------------------------\n");
    for (i=0; i<HASH_TBL_SIZE; i++) {
        if (rst_hashtbl[i]) {
            struct inode *cur;
            for (cur=rst_hashtbl[i]; cur!=NULL; cur=cur->next) {
                if (cur == rst_hashtbl[i]) 
                    printf("| %5u |", i);
                else
                    printf("|          |");
                    
                snprintf(buffer, 64, " <%u, %u, %u, %u>, %d, [%u] ",
                        rst_hashtbl[i]->key->sip, 
                        rst_hashtbl[i]->key->dip, 
                        rst_hashtbl[i]->key->sport, 
                        rst_hashtbl[i]->key->dport, 
                        rst_hashtbl[i]->value, 
                        (unsigned int)rst_hashtbl[i]->ts); 
                printf("%-64s |\n", buffer);
            }
        }
    }
    printf("---------------------------------------------------------------------------\n");
}

void summary_icache()
{
    int i;
    int count = 0;
    int max = 0;
    for (i=0; i<HASH_TBL_SIZE; i++) {
        if (rst_hashtbl[i]) {
            count++;
            int x = 0;
            struct inode *cur;
            for (cur=rst_hashtbl[i]; cur!=NULL; cur=cur->next)
                x++;
            if (x > max)
                max = x;
        }
    }
    printf("Utilization rate: %f\n", ((float)count)/HASH_TBL_SIZE);
    printf("Max length: %d\n", max);
}

void dump_scache()
{
    int i;
    char buffer[1000];
    printf("---------------------------------------------------------------------------\n");
    for (i=0; i<HASH_TBL_SIZE; i++) {
        if (httpreq_hashtbl[i]) {
            struct snode *cur;
            for (cur=httpreq_hashtbl[i]; cur!=NULL; cur=cur->next) {
                if (cur == httpreq_hashtbl[i]) 
                    printf("| %5u |", i);
                else
                    printf("|          |");
                    
                snprintf(buffer, 1000, " <%u, %u, %u, %u>, %s, [%u] ",
                        httpreq_hashtbl[i]->key->sip, 
                        httpreq_hashtbl[i]->key->dip, 
                        httpreq_hashtbl[i]->key->sport, 
                        httpreq_hashtbl[i]->key->dport, 
                        httpreq_hashtbl[i]->value, 
                        (unsigned int)httpreq_hashtbl[i]->ts); 
                printf("%-80s |\n", buffer);
            }
        }
    }
    printf("---------------------------------------------------------------------------\n");
}

void summary_scache()
{
    int i;
    int count = 0;
    int max = 0;
    for (i=0; i<HASH_TBL_SIZE; i++) {
        if (httpreq_hashtbl[i]) {
            count++;
            int x = 0;
            struct snode *cur;
            for (cur=httpreq_hashtbl[i]; cur!=NULL; cur=cur->next)
                x++;
            if (x > max)
                max = x;
        }
    }
    printf("Utilization rate: %f\n", ((float)count)/HASH_TBL_SIZE);
    printf("Max length: %d\n", max);
}


/*
 * RST cache
 * records received RST packets in last a few seconds
 */

static struct array_cache rst_cache;

void rst_cache_init()
{
    array_cache_init(&rst_cache, 100, 3);
}

int get_rst_count(struct fourtuple *fourtp)
{
    unsigned int key = make_hash(fourtp);
    int *cnt;
    if ((cnt = (int*)array_cache_get(&rst_cache, key)) == NULL)
        return 0;
    else
        return *cnt;
}

int set_rst_count(struct fourtuple *fourtp, int cnt)
{
    unsigned int key = make_hash(fourtp);
    int *v = (int*)malloc(sizeof(int));
    *v = cnt;
    return array_cache_set(&rst_cache, key, v);
}

/*
 * HTTP cache
 * records HTTP requests sent in last a few seconds
 */

static struct array_cache http_cache;

void http_cache_init()
{
    array_cache_init(&http_cache, 5000, 5);
}

char* get_last_http_request(struct fourtuple *fourtp)
{
    unsigned int key = make_hash(fourtp);
    return (char*)array_cache_get(&http_cache, key);
}

int set_last_http_request(struct fourtuple *fourtp, char *httpreq)
{
    unsigned int key = make_hash(fourtp);
    char *h = (char*)malloc(1024);
    h[0] = 0;
    strncat(h, httpreq, 1024);
    return array_cache_set(&http_cache, key, h);
}

/*
 * DNS cache
 * records DNS requests sent over TCP in last a few seconds
 */

static struct array_cache dns_cache;

void dns_cache_init()
{
    array_cache_init(&dns_cache, 1000, 10);
}

struct fourtuple* dns_cache_get(unsigned int key)
{
    return (struct fourtuple*)array_cache_get(&dns_cache, key);
}

int dns_cache_set(unsigned int key, struct fourtuple *fourtp)
{
    struct fourtuple *f = (struct fourtuple*)malloc(sizeof(struct fourtuple));
    f->sip = fourtp->sip;
    f->dip = fourtp->dip;
    f->sport = fourtp->sport;
    f->dport = fourtp->dport;
    return array_cache_set(&dns_cache, key, f);
}


int init_cache()
{
    rst_cache_init();
    http_cache_init();
    dns_cache_init();
}


