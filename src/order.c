
/*
 * Order queue
 * used for the unidirection communication from main thread to caching thread
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h> 

#include "logging.h"


#define ORDER_QUEUE_SIZE 1024

struct order {
    int type;
    void *data;
};

/* cyclic queue */
static struct order order_queue[ORDER_QUEUE_SIZE];
/* head is the index of first unprocessed order */
static unsigned int head = 0;
/* tail is the index of first available space */
static unsigned int tail = 0;

static int is_empty = 1;

static int is_full = 0;

static pthread_mutex_t lock;

void order(int type, void *data)
{
    //log_debugv("order(): head=%d, tail=%d, is_empty=%d, is_full=%d", head, tail, is_empty, is_full);
    if (is_full) {
        log_error("Order queue is full. Order is dropped.");
        return;
    }

    pthread_mutex_lock(&lock);
    order_queue[tail].type = type;
    order_queue[tail].data = data;
    tail = (tail + 1) % ORDER_QUEUE_SIZE;
    if (tail == head) is_full = 1;
    is_empty = 0;
    pthread_mutex_unlock(&lock);
    log_debugv("order(): head=%d, tail=%d, is_empty=%d, is_full=%d", head, tail, is_empty, is_full);
}

int get_order(void **data)
{
    log_debugv("get_order(): head=%d, tail=%d, is_empty=%d, is_full=%d", head, tail, is_empty, is_full);
    int type;

    if (is_empty) return 0;

    pthread_mutex_lock(&lock);
    *data = order_queue[head].data;
    type = order_queue[head].type;
    head = (head + 1) % ORDER_QUEUE_SIZE;
    if (head == tail) is_empty = 1;
    is_full = 0;
    pthread_mutex_unlock(&lock);

    //log_debugv("get_order(): head=%d, tail=%d, is_empty=%d, is_full=%d", head, tail, is_empty, is_full);
    // remember to free data after usage
    return type;
}


