/*
 * In-memory LRU cache.
 * Loading data from redis when starting up, Saving to redis when exiting.
 * Implemented usnig a linked-list and a hash table
 * TODO:
 * 1. The functions for per-connection and per-host cache are somehow duplicate.
 *    Need to be cleaned.
 */

#include "memcache.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "logging.h"
#include "protocol.h"
#include "helper.h"
#include "strategy.h"
#include "redis.h"


#define MAX_CACHE_SIZE 65535

#define HASH_TABLE_SIZE 65535

#define DEFAULT_VALIDITY_PERIOD 600


// Per-connection cache, maintain connection context, e.g. strategy used

struct conn_info_ll_node
{
    unsigned int saddr;
    unsigned short sport;
    unsigned int daddr;
    unsigned short dport;
    int sid;
    time_t ts;
    struct conn_info_ll_node *prev; 
    struct conn_info_ll_node *next; 
};

struct conn_info_ht_node
{
    struct conn_info_ll_node *node;
    struct conn_info_ht_node *next;
};

static struct conn_info_ll_node* conn_info_list = NULL;
static unsigned int conn_info_list_len = 0;

static struct conn_info_ht_node* conn_info_hashtbl[HASH_TABLE_SIZE];


// Per-target-IP cache, maintain IP/Host specific information, 
// e.g. TTL, historical result

struct host_info_ll_node
{
    unsigned int daddr;
    unsigned char ttl;
    struct historical_result *hist_res;
    // TODO: store more host-specific information, e.g. whether each discrepancy
    // is applicable to a particular host. Some discrepancies may require client-side
    // support, e.g. wrong checksum, which should be stored as client-side information
    time_t ts;
    struct host_info_ll_node *prev;
    struct host_info_ll_node *next;
};

struct host_info_ht_node
{
    struct host_info_ll_node *node;
    struct host_info_ht_node *next;
};

static struct host_info_ll_node* host_info_list = NULL;
static unsigned int host_info_list_len = 0;

static struct host_info_ht_node* host_info_hashtbl[HASH_TABLE_SIZE];


/**********************************/
/* Per-connection cache functions */
/**********************************/

// Display summary of per-connection cache
void conn_info_cache_summary()
{
    // Linked list
    printf("Linked list size: %d\n", conn_info_list_len);
    printf("Linked list max size: %d\n", MAX_CACHE_SIZE);
    printf("Linked list utilization rate: %u/%u(%f)\n", conn_info_list_len, MAX_CACHE_SIZE, ((float)conn_info_list_len/MAX_CACHE_SIZE));

    // Hash table
    int i;
    int count = 0;
    int max = 0;
    for (i=0; i<HASH_TABLE_SIZE; i++) {
        if (conn_info_hashtbl[i]) {
            count++;
            int x = 0;
            struct conn_info_ht_node *hn;
            for (hn = conn_info_hashtbl[i]; hn != NULL; hn = hn->next)
                x++;
            if (x > max)
                max = x;
        }
    }

    printf("Hash table utilization rate: %f\n", ((float)count)/HASH_TABLE_SIZE);
    printf("Hash table max length: %d\n", max);
}

// Display contents of per-connection cache
void conn_info_cache_dump()
{
    // Linked list
    int i;
    char sip[16], dip[16];
    struct conn_info_ll_node *ln;
    printf("Linked list dump:\n");
    for (i = 1, ln = conn_info_list; ln != NULL; ln = ln->next, i++) {
        printf("%d. %s:%d-%s:%d\t%d\n", i, ip2str(ln->saddr, sip), ntohs(ln->sport), ip2str(ln->daddr, dip), ntohs(ln->dport), ln->sid);
    }

    // Hash table
    char buffer[64];
    printf("Hash table dump:\n");
    printf("---------------------------\n");
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        if (conn_info_hashtbl[i]) {
            struct conn_info_ht_node *hn;
            for (hn = conn_info_hashtbl[i]; hn != NULL; hn = hn->next) {
                if (hn == conn_info_hashtbl[i]) 
                    printf("| %5u |", i);
                else
                    printf("|          |");
                    
                snprintf(buffer, 64, " <%p> ", hn->node);
                printf("%-16s |\n", buffer);
            }
        }
    }
    printf("---------------------------\n");
}

// Clean the cache and remove old entries
// We don't want to discard any valid entry so far, just remove those expired.
void clean_conn_info_cache()
{
    time_t now = time(NULL);

    struct conn_info_ll_node *ln, *to_be_freed = NULL;
    for (ln = conn_info_list; ln != NULL; ln = ln->next) {
        if (ln->ts > DEFAULT_VALIDITY_PERIOD) {
            // remove the node from the linked list
            if (ln == conn_info_list) {
                // if is head, replace the head with the second
                conn_info_list = ln->next;
                conn_info_list->prev = NULL;
            }
            else {
                // if is not head
                ln->prev->next = ln->next;
                ln->next->prev = ln->prev;
            }
            // insert it into the to-be-freed list and free its memory later
            ln->next = to_be_freed;
            ln->prev = NULL;
            to_be_freed = ln;

            // remove the node from the hash table
            unsigned int hash = make_hash2(ln->saddr, ln->sport, ln->daddr, ln->dport);
            struct conn_info_ht_node *hn, *hn2;
            hn = conn_info_hashtbl[hash % HASH_TABLE_SIZE];
            if (hn->node == ln) {
                // if is head, replace the head with the second
                conn_info_hashtbl[hash % HASH_TABLE_SIZE] = hn->next;
            }
            else {
                // if is not head, remove the node and splice the list
                for (; hn != NULL; hn = hn->next) {
                    if (hn->next && hn->next->node == ln) {
                        hn2 = hn->next;
                        hn->next = hn->next->next;
                        free(hn2);
                        break;
                    }
                }
            }
        }
    }

    // free memory of linked list nodes
    for (ln = to_be_freed; ln != NULL; ) {
        struct conn_info_ll_node *last = ln;
        ln = ln->next;
        free(last);
    }
}

struct conn_info_ll_node* create_conn_info_entry(struct fourtuple *f) {
    unsigned int hash = make_hash(f);

    struct conn_info_ll_node *ln = (struct conn_info_ll_node*)malloc(sizeof(struct conn_info_ll_node));
    ln->saddr = f->saddr;
    ln->sport = f->sport;
    ln->daddr = f->daddr;
    ln->dport = f->dport;
    ln->sid = 0;
    ln->ts = time(NULL);
    ln->prev = NULL;
    ln->next = conn_info_list;
    if (conn_info_list) {
        conn_info_list->prev = ln;
    }
    conn_info_list = ln;
    conn_info_list_len++;
    
    struct conn_info_ht_node *hn = (struct conn_info_ht_node*)malloc(sizeof(struct conn_info_ht_node));
    hn->node = ln;
    hn->next = conn_info_hashtbl[hash % HASH_TABLE_SIZE];
    conn_info_hashtbl[hash % HASH_TABLE_SIZE] = hn;

    return ln;
}

// Set the Strategy ID to the connection
void set_sid(struct fourtuple *f, int sid)
{
    struct conn_info_ll_node *ln;
    struct conn_info_ht_node *hn;

    unsigned int hash = make_hash(f);

    // check if exists
    for (hn = conn_info_hashtbl[hash % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->saddr == f->saddr &&
                ln->sport == f->sport &&
                ln->daddr == f->daddr &&
                ln->dport == f->dport) {
            ln->sid = sid;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = conn_info_list;
                conn_info_list->prev = ln;
                conn_info_list = ln;
            }
            return;
        }
    }

    // doesn't exist, need to create a new node
    if (conn_info_list_len > MAX_CACHE_SIZE) {
        clean_conn_info_cache();
        if (conn_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-connection cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_conn_info_entry(f);
    ln->sid = sid;

    // debug
    //conn_info_cache_summary();
    //conn_info_cache_dump();
}

// Retrieve the Strategy ID binded to the connection
int get_sid(struct fourtuple *f)
{
    struct conn_info_ll_node *ln;
    struct conn_info_ht_node *hn;

    unsigned int hash = make_hash(f);
    for (hn = conn_info_hashtbl[hash % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->saddr == f->saddr &&
                ln->sport == f->sport &&
                ln->daddr == f->daddr &&
                ln->dport == f->dport) {
            return ln->sid;
        }
    }
    return -1;
}


/****************************/
/* Per-host cache functions */
/****************************/

// Display summary of per-host cache
void host_info_cache_summary()
{
    // Linked list
    printf("Linked list size: %d\n", host_info_list_len);
    printf("Linked list max size: %d\n", MAX_CACHE_SIZE);
    printf("Linked list utilization rate: %u/%u(%f)\n", host_info_list_len, MAX_CACHE_SIZE, ((float)host_info_list_len/MAX_CACHE_SIZE));

    // Hash table
    int i;
    int count = 0;
    int max = 0;
    for (i=0; i<HASH_TABLE_SIZE; i++) {
        if (host_info_hashtbl[i]) {
            count++;
            int x = 0;
            struct host_info_ht_node *hn;
            for (hn = host_info_hashtbl[i]; hn != NULL; hn = hn->next)
                x++;
            if (x > max)
                max = x;
        }
    }

    printf("Hash table utilization rate: %f\n", ((float)count)/HASH_TABLE_SIZE);
    printf("Hash table max length: %d\n", max);
}

// Display contents of per-host cache
void host_info_cache_dump()
{
    // Linked list
    int i, j;
    char dip[16];
    struct host_info_ll_node *ln;
    printf("Linked list dump:\n");
    for (i = 1, ln = host_info_list; ln != NULL; ln = ln->next, i++) {
        printf("%d. %s. TTL=%d. ", i, ip2str(ln->daddr, dip), ln->ttl);
        for (j = 0; j < g_strat_num; j++) {
            if (ln->hist_res[j].succ || ln->hist_res[j].fail1 || ln->hist_res[j].fail2) {
                printf("SID: %d(%d, %d, %d). ", j, ln->hist_res[j].succ,
                        ln->hist_res[j].fail1, ln->hist_res[j].fail2);
            }
        }
        printf("\n");
    }

    /*
    // Hash table
    char buffer[64];
    printf("Hash table dump:\n");
    printf("---------------------------\n");
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        if (host_info_hashtbl[i]) {
            struct host_info_ht_node *hn;
            for (hn = host_info_hashtbl[i]; hn != NULL; hn = hn->next) {
                if (hn == host_info_hashtbl[i]) 
                    printf("| %5u |", i);
                else
                    printf("|          |");
                    
                snprintf(buffer, 64, " <%p> ", hn->node);
                printf("%-16s |\n", buffer);
            }
        }
    }
    printf("---------------------------\n");
    */
}

// Clean the cache and remove old entries
// We don't want to discard any valid entry so far, just remove those expired.
void clean_host_info_cache()
{
    time_t now = time(NULL);

    struct host_info_ll_node *ln, *to_be_freed = NULL;
    for (ln = host_info_list; ln != NULL; ln = ln->next) {
        if (ln->ts > DEFAULT_VALIDITY_PERIOD) {
            // remove the node from the linked list
            if (ln == host_info_list) {
                // if is head, replace the head with the second
                host_info_list = ln->next;
                host_info_list->prev = NULL;
            }
            else {
                // if is not head
                ln->prev->next = ln->next;
                ln->next->prev = ln->prev;
            }
            // insert it into the to-be-freed list and free its memory later
            ln->next = to_be_freed;
            ln->prev = NULL;
            to_be_freed = ln;

            // remove the node from the hash table
            unsigned int hash = ln->daddr;
            struct host_info_ht_node *hn, *hn2;
            hn = host_info_hashtbl[hash % HASH_TABLE_SIZE];
            if (hn->node == ln) {
                // if is head, replace the head with the second
                host_info_hashtbl[hash % HASH_TABLE_SIZE] = hn->next;
            }
            else {
                // if is not head, remove the node and splice the list
                for (; hn != NULL; hn = hn->next) {
                    if (hn->next && hn->next->node == ln) {
                        hn2 = hn->next;
                        hn->next = hn->next->next;
                        free(hn2);
                        break;
                    }
                }
            }
        }
    }

    // free memory of linked list nodes
    for (ln = to_be_freed; ln != NULL; ) {
        struct host_info_ll_node *last = ln;
        ln = ln->next;
        free(last->hist_res);
        free(last);
    }
}

struct host_info_ll_node* create_host_info_entry(unsigned int daddr) {
    struct host_info_ll_node *ln = (struct host_info_ll_node*)malloc(sizeof(struct host_info_ll_node));
    ln->hist_res = (struct historical_result*)calloc(sizeof(struct historical_result), g_strat_num);
    ln->daddr = daddr;
    ln->ttl = 0;
    ln->ts = time(NULL);
    ln->prev = NULL;
    ln->next = host_info_list;
    if (host_info_list) {
        host_info_list->prev = ln;
    }
    host_info_list = ln;
    host_info_list_len++;
    
    struct host_info_ht_node *hn = (struct host_info_ht_node*)malloc(sizeof(struct host_info_ht_node));
    hn->node = ln;
    hn->next = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
    host_info_hashtbl[daddr % HASH_TABLE_SIZE] = hn;

    return ln;
}

void set_ttl(unsigned int daddr, unsigned char ttl) 
{
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // check if exists 
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->ttl = ttl;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    // doesn't exist, need to create a new node
    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->ttl = ttl;

    // debug
    //host_info_cache_summary();
    //host_info_cache_dump();
}

void set_ttl_if_lt(unsigned int daddr, unsigned char ttl) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // check if exists 
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            if (ttl < ln->ttl) {
                ln->ttl = ttl;
                // move it to the head
                if (ln->prev) {
                    ln->prev->next = ln->next;
                    if (ln->next) {
                        ln->next->prev = ln->prev;
                    }
                    ln->prev = NULL;
                    ln->next = host_info_list;
                    host_info_list->prev = ln;
                    host_info_list = ln;
                }
            }
            return;
        }
    }
}

unsigned char get_ttl(unsigned int daddr) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            return ln->ttl;
        }
    }
    return 0;
}

void incr_ttl(unsigned int daddr) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->ttl++;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    // create an entry if not exist
    ln = create_host_info_entry(daddr);
    ln->ttl = 32; // default initial TTL, need a better way to find initial TTL
}

void decr_ttl(unsigned int daddr) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->ttl--;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    // create an entry if not exist
    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->ttl = 32; // default initial TTL, need a better way to find initial TTL
}

void incr_succ(unsigned int daddr, int sid) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // Check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->hist_res[sid].succ++;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->hist_res[sid].succ++;
}

void incr_fail1(unsigned int daddr, int sid) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // Check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->hist_res[sid].fail1++;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->next->prev = ln->prev;
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->hist_res[sid].fail1++;
}

void incr_fail2(unsigned int daddr, int sid) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // Check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->hist_res[sid].fail2++;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->hist_res[sid].fail2++;
}

void set_succ(unsigned int daddr, int sid, int val) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // Check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->hist_res[sid].succ = val;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->hist_res[sid].succ = val;
}

void set_fail1(unsigned int daddr, int sid, int val) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // Check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->hist_res[sid].fail1 = val;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->hist_res[sid].succ = val;
}

void set_fail2(unsigned int daddr, int sid, int val) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    // Check if exists
    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            ln->hist_res[sid].fail2 = val;
            // move it to the head
            if (ln->prev) {
                ln->prev->next = ln->next;
                if (ln->next) {
                    ln->next->prev = ln->prev;
                }
                ln->prev = NULL;
                ln->next = host_info_list;
                host_info_list->prev = ln;
                host_info_list = ln;
            }
            return;
        }
    }

    if (host_info_list_len > MAX_CACHE_SIZE) {
        clean_host_info_cache();
        if (host_info_list_len > MAX_CACHE_SIZE) {
            printf("Warning! Per-host cache is full! Enlarge the cache or discard old entries.\n");
            // TODO: discard old entries
            return;
        }
    }

    ln = create_host_info_entry(daddr);
    ln->hist_res[sid].succ = val;
}

struct historical_result *get_hist_res(unsigned int daddr) {
    struct host_info_ll_node *ln;
    struct host_info_ht_node *hn;

    for (hn = host_info_hashtbl[daddr % HASH_TABLE_SIZE];
            hn != NULL && hn->node != NULL ; hn = hn->next) {
        ln = hn->node;
        if (ln->daddr == daddr) {
            return ln->hist_res;
        }
    }
    return NULL;
}


int load_ttl_from_redis()
{
    log_info("Loading TTL from redis.");
    char keys[65536][64]; // load 65536 entries at maximum, is it enough?
    unsigned int daddr;
    char dip[16];

    int count = scan_match("ttl:*", keys, 65536);
    // TODO: bulk load
    for (int i = 0; i < count; i++) {
        sscanf(keys[i], "ttl:%u", &daddr);
        ip2str(daddr, dip);
        int ttl = get_int(keys[i]);
        set_ttl(daddr, ttl);
    }
    log_debug("%d records loaded.", count);
    return count;
}

int save_ttl_to_redis() 
{
    log_info("Saving TTL to redis");
    char key[64];
    struct host_info_ll_node *ln;
    int count = 0;
    
    // TODO: bulk save
    for (ln = host_info_list; ln != NULL; ln = ln->next) {
        sprintf(key, "ttl:%u", ln->daddr);
        set_int_ex(key, ln->ttl, 31536000); // expire in 1 year
        count++;
    }
    log_debug("%d records saved.", count);
    return count;
}

void save_historical_result_to_redis() {
    log_info("Saving historical results to redis.");

    // We don't do it for now, because it will update the expiration time 
    // of the records in redis. It's better to let old records expire.
}

void load_historical_result_from_redis() {
    log_info("Loading historical results from redis.");
    char keys[65536][64]; // load 65536 entries at maximum, is it enough?
    int sid;
    unsigned int daddr;
    char dip[16];
    char res[16];

    int count = scan_match("strategy:stats:*", keys, 65536);
    // TODO: bulk load
    for (int i = 0; i < count; i++) {
        sscanf(keys[i], "strategy:stats:%d:%u:%s", &sid, &daddr, res);
        ip2str(daddr, dip);
        int val = get_int(keys[i]);
        log_debugv("IP: %s. SID: %d. %s: %d", dip, sid, res, val);
        if (strcmp(res, "succ") == 0) {
            set_succ(daddr, sid, val);
        }
        else if (strcmp(res, "fail1") == 0) {
            set_fail1(daddr, sid, val);
        }
        else if (strcmp(res, "fail2a") == 0 || strcmp(res, "fail2b") == 0) {
            set_fail2(daddr, sid, val);
        }
        else {
            log_error("Unexpected result. IP: %s. SID: %d. Result: %s", dip, sid, res);
        }
    }
    log_debug("%d records loaded.", count);
}

