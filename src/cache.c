/*
 * Caching thread
 * A worker thread taking orders from the main thread
 * mainly interacts with the external redis cache.
 */

#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ev.h>

#include "protocol.h"
#include "socket.h"
#include "logging.h"
#include "order.h"
#include "redis.h"
#include "strategy.h"
#include "helper.h"
#include "dns.h"
#include "dnscli.h"
#include "memcache.h"
#include "ttl_probing.h"


// for debug 
struct timespec ts;
double t1, t2;

struct dns_udp_request_info {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    u_int16_t txn_id;
    char qname[MAX_QNAME_LEN+1];
};

struct dns_udp_response_info {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    u_int16_t txn_id;
    char qname[MAX_QNAME_LEN+1];
    //unsigned int checksum;
    unsigned char ttl;
};

struct dns_tcp_response_info {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    u_int32_t seq;
    u_int8_t ttl;
    u_int16_t txn_id;
    char qname[MAX_QNAME_LEN+1];
    char payload[MAX_PACKET_SIZE];
    unsigned short payload_len;
};

struct http_request_info {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    char req_line[MAX_REQLINE_LEN+1];
};

struct http_response_info {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    u_int32_t seq;
    u_int8_t ttl;
};

struct strategy_info {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    int sid;
};

/**********************************
 * Requests waiting for responses *
 **********************************/

#define MAX_PENDING_REQUESTS_NUM 65535

struct pending_request {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    ev_tstamp expire;
};

static struct pending_request prq[MAX_PENDING_REQUESTS_NUM];

static ev_tstamp timeout = REQ_WAIT_RESP_TIMEOUT;
static ev_timer timer;

// head is the index of the first pending request 
static unsigned int prq_head = 0;
// tail is the index of the first available space 
static unsigned int prq_tail = 0;

static int prq_is_empty = 1;

static int prq_is_full = 0;

/*********
 * libev *
 *********/

static ev_async order_watcher;

static void order_cb(EV_P_ ev_async *w, int revents);
static void ev_timer_cb(EV_P_ ev_timer *w, int revents);



/*******************************
 * Called from the main thread *
 *******************************/

void init_ev_watchers()
{
    ev_async_init(&order_watcher, order_cb);
    ev_async_start(EV_DEFAULT_ &order_watcher);

    ev_init(&timer, ev_timer_cb);
}

void cache_strategy(const struct fourtuple *fourtp, int sid)
{
    struct strategy_info *info = (struct strategy_info*)malloc(sizeof(struct strategy_info));
    info->saddr = fourtp->saddr;
    info->daddr = fourtp->daddr;
    info->sport = fourtp->sport;
    info->dport = fourtp->dport;
    info->sid = sid;

    order(ORDER_CACHE_STRATEGY, info);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void cache_dns_udp_request(unsigned short txn_id, const char *qname, const struct fourtuple *fourtp)
{
    struct dns_udp_request_info *info = (struct dns_udp_request_info*)malloc(sizeof(struct dns_udp_request_info));
    info->saddr = fourtp->saddr;
    info->daddr = fourtp->daddr;
    info->sport = fourtp->sport;
    info->dport = fourtp->dport;
    info->txn_id = txn_id;
    info->qname[0] = 0;
    strncat(info->qname, qname, MAX_QNAME_LEN);

    order(ORDER_CACHE_DNS_UDP_REQUEST, info);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void cache_dns_tcp_request(const struct fourtuple *fourtp)
{
    struct fourtuple *f = (struct fourtuple*)malloc(sizeof(struct fourtuple));
    f->saddr = fourtp->saddr;
    f->daddr = fourtp->daddr;
    f->sport = fourtp->sport;
    f->dport = fourtp->dport;

    order(ORDER_CACHE_DNS_TCP_REQUEST, f);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void process_dns_udp_response(unsigned short txn_id, const char *qname, const struct fourtuple *fourtp, unsigned char ttl)
{
    struct dns_udp_response_info *info = (struct dns_udp_response_info*)malloc(sizeof(struct dns_udp_response_info));
    info->saddr = fourtp->saddr;
    info->daddr = fourtp->daddr;
    info->sport = fourtp->sport;
    info->dport = fourtp->dport;
    info->txn_id = txn_id;
    info->qname[0] = 0;
    strncat(info->qname, qname, MAX_QNAME_LEN);
    //info->checksum = calc_checksum(payload, payload_len);
    info->ttl = ttl;

    order(ORDER_PROC_DNS_UDP_RESPONSE, info);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void process_dns_tcp_response(unsigned short txn_id, const char *qname, const struct fourtuple *fourtp, unsigned int seq, unsigned char ttl, const unsigned char *payload, unsigned short payload_len)
{
    struct dns_tcp_response_info *info = (struct dns_tcp_response_info*)malloc(sizeof(struct dns_tcp_response_info));
    info->saddr = fourtp->saddr;
    info->daddr = fourtp->daddr;
    info->sport = fourtp->sport;
    info->dport = fourtp->dport;
    info->seq = seq;
    info->ttl = ttl;
    info->txn_id = txn_id;
    info->qname[0] = 0;
    strncat(info->qname, qname, MAX_QNAME_LEN);
    memcpy(info->payload, payload, payload_len);
    info->payload_len = payload_len;

    order(ORDER_PROC_DNS_TCP_RESPONSE, info);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void cache_http_request(const struct fourtuple *fourtp, const char *req_line)
{
    struct http_request_info *info = (struct http_request_info*)malloc(sizeof(struct http_request_info));
    info->saddr = fourtp->saddr;
    info->daddr = fourtp->daddr;
    info->sport = fourtp->sport;
    info->dport = fourtp->dport;
    info->req_line[0] = 0;
    strncat(info->req_line, req_line, MAX_REQLINE_LEN);

    order(ORDER_CACHE_HTTP_REQUEST, info);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void process_http_response(const struct fourtuple *fourtp, unsigned int seq, unsigned char ttl)
{
    struct http_response_info *info = (struct http_response_info*)malloc(sizeof(struct http_response_info));
    info->saddr = fourtp->saddr;
    info->daddr = fourtp->daddr;
    info->sport = fourtp->sport;
    info->dport = fourtp->dport;
    info->seq = seq;
    info->ttl = ttl;

    order(ORDER_PROC_HTTP_RESPONSE, info);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void process_incoming_RST(const struct mypacket *packet)
{
    struct tcpinfo *info = (struct tcpinfo*)malloc(sizeof(struct tcpinfo));
    info->saddr = packet->iphdr->saddr;
    info->daddr = packet->iphdr->daddr;
    info->sport = packet->tcphdr->th_sport;
    info->dport = packet->tcphdr->th_dport;
    info->flags = packet->tcphdr->th_flags;
    info->seq = packet->tcphdr->th_seq;
    info->ack = packet->tcphdr->th_ack;
    info->ttl = packet->iphdr->ttl;
    info->win = packet->tcphdr->th_win;
    info->fragoff = packet->iphdr->frag_off;

    order(ORDER_PROC_INCOMING_RST, info);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void need_evaluation(const struct fourtuple *fourtp)
{
    struct fourtuple *f = (struct fourtuple*)malloc(sizeof(struct fourtuple));
    f->saddr = fourtp->saddr;
    f->daddr = fourtp->daddr;
    f->sport = fourtp->sport;
    f->dport = fourtp->dport;

    order(ORDER_NEED_EVAL, f);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

void remove_vflag(const struct fourtuple *fourtp)
{
    struct fourtuple *f = (struct fourtuple*)malloc(sizeof(struct fourtuple));
    f->saddr = fourtp->saddr;
    f->daddr = fourtp->daddr;
    f->sport = fourtp->sport;
    f->dport = fourtp->dport;

    order(ORDER_REMOVE_VFLAG, f);
    ev_async_send(EV_DEFAULT_ &order_watcher);
}

/************************************
 * Executed from the caching thread *
 ************************************/

static void save_sid(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport, int sid)
{
    char key[64];
    sprintf(key, "strategy:conn:%u_%hu_%u_%hu", saddr, sport, daddr, dport);
    set_int_ex(key, sid, 1800);
}

static int load_sid(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport)
{
    char key[64];
    // retrieve strategy used for this connection
    sprintf(key, "strategy:conn:%u_%hu_%u_%hu", saddr, sport, daddr, dport);
    return get_int(key);
}

static void set_vflag(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport)
{
    char key[64];
    sprintf(key, "strategy:need_verify:%u_%hu_%u_%hu", saddr, sport, daddr, dport);
    set_int_ex_nx(key, 1, STRATEGY_VERIFICATION_TIMEOUT);
}

static int get_vflag(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport)
{
    char key[64];
    sprintf(key, "strategy:need_verify:%u_%hu_%u_%hu", saddr, sport, daddr, dport);
    return get_int(key);
}

static void clear_vflag(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport)
{
    char key[64];
    sprintf(key, "strategy:need_verify:%u_%hu_%u_%hu", saddr, sport, daddr, dport);
    del_key(key);
}

static void set_verified(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport)
{
    char key[64];
    sprintf(key, "strategy:verified:%u_%hu_%u_%hu", saddr, sport, daddr, dport);
    set_int_ex_nx(key, 1, STRATEGY_VERIFIED_TIMEOUT);
}

static int get_verified(u_int32_t saddr, u_int16_t sport, u_int32_t daddr, u_int16_t dport)
{
    char key[64];
    sprintf(key, "strategy:verified:%u_%hu_%u_%hu", saddr, sport, daddr, dport);
    return get_int(key);
}

static void set_aflag1(u_int32_t saddr, u_int32_t daddr)
{
    char key[64];
    sprintf(key, "rst:attack1:%u_%u", saddr, daddr);
    set_int_ex_nx(key, 1, RST_ATTACK_TIMEOUT);
}

static int get_aflag1(u_int32_t saddr, u_int32_t daddr)
{
    char key[64];
    sprintf(key, "rst:attack1:%u_%u", saddr, daddr);
    return get_int(key);
}

static void set_aflag2(u_int32_t saddr, u_int32_t daddr)
{
    char key[64];
    sprintf(key, "rst:attack2:%u_%u", saddr, daddr);
    set_int_ex_nx(key, 1, RST_ATTACK_TIMEOUT);
}

static int get_aflag2(u_int32_t saddr, u_int32_t daddr)
{
    char key[64];
    sprintf(key, "rst:attack2:%u_%u", saddr, daddr);
    return get_int(key);
}

static inline unsigned int is_ttl_in_set(unsigned char ttl, unsigned int ttl_set)
{
    return (ttl_set & 0xff) == ttl || ((ttl_set >> 8) & 0xff) == ttl || 
    ((ttl_set >> 16) & 0xff) == ttl || ((ttl_set >> 24) & 0xff) == ttl;
}

static inline unsigned int insert_ttl(unsigned char ttl, unsigned int ttl_set)
{
    return (ttl_set << 8) + ttl;
}

void _need_evaluation(struct fourtuple *fourtp)
{
    if (!get_verified(fourtp->saddr, fourtp->sport, fourtp->daddr, fourtp->dport)) {
        log_debugv("Set V flag.");
        set_vflag(fourtp->saddr, fourtp->sport, fourtp->daddr, fourtp->dport);
    }
    free(fourtp);
}

void _remove_vflag(struct fourtuple *fourtp)
{
    clear_vflag(fourtp->saddr, fourtp->sport, fourtp->daddr, fourtp->dport);
    free(fourtp);
}

// (obselete) use get_sid()/set_sid() in memcache.c instead
void _cache_strategy(struct strategy_info *info)
{
    // label connection with strategy id 
    save_sid(info->saddr, info->sport, info->daddr, info->dport, info->sid);

    free(info);
}

/* Cache DNS requests sent over TCP to match the responses. If there're multiple requests
 * with the same transaction ID and query domain name, only the first one will be cached
 * Hold the a request for a short period or until a response is received. */
void _cache_dns_udp_request(struct dns_udp_request_info *info)
{
    char key[MAX_QNAME_LEN+100], val[100];
    sprintf(key, "dns:req:%u_%s", info->txn_id, info->qname);
    sprintf(val, "%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
    set_str_ex_nx(key, val, DNS_UDP_REQ_CACHE_TIMEOUT);

    free(info);
}

void _cache_dns_tcp_request(struct fourtuple *fourtp)
{
    char key[100];
    //sprintf(key, "dns:wait_resp:%u_%hu_%u_%hu", fourtp->saddr, fourtp->sport, fourtp->daddr, fourtp->dport);
    //set_int_ex_nx(key, 1, REQ_WAIT_RESP_TIMEOUT);
    // Redis doesn't provide a timely notification event when key expires, so we set up a timer using ev_timer 
    if (prq_is_full) {
        log_error("Pending request queue is full! Request is ignored.");
        free(fourtp);
        return;
    } else {
        prq[prq_tail].saddr = fourtp->saddr;
        prq[prq_tail].daddr = fourtp->daddr;
        prq[prq_tail].sport = fourtp->sport;
        prq[prq_tail].dport = fourtp->dport;
        prq[prq_tail].expire = ev_time() + timeout;
        prq_tail = (prq_tail + 1) % MAX_PENDING_REQUESTS_NUM;
        if (prq_tail == prq_head) prq_is_full = 1;
        if (prq_is_empty) {
            ev_timer_set(&timer, timeout, 0);
            ev_timer_start(EV_DEFAULT_ &timer);
            prq_is_empty = 0;
        }
        log_debugv("PRQ enqueue: head=%d, tail=%d, is_empty=%d, is_full=%d", prq_head, prq_tail, prq_is_empty, prq_is_full);
        log_debugv("PRQ head: %u_%hu_%u_%hu %f", prq[prq_head].saddr, prq[prq_head].sport, prq[prq_head].daddr, prq[prq_head].dport, prq[prq_head].expire);
    }

    free(fourtp);
}

// Cache the response in a short period to see if there're multiple responses 
void _process_dns_udp_response(struct dns_udp_response_info *info)
{
    char key[MAX_QNAME_LEN+100], val[100];
    unsigned int checksum;

    sprintf(key, "dns:resp:%u_%s_%u_%hu_%u_%hu", info->txn_id, info->qname, info->saddr, info->sport, info->daddr, info->dport);
    get_str(key, val, 100);
    if (val[0] != 0) {
        if (strtol(val, NULL, 10) != info->ttl) {
            // received two different DNS responses from the same server
            // looks like it has been poisoned 
            log_info("[EVAL] PROBABLY POISONED DOMAIN: %s", info->qname);

            char key2[100];
            sprintf(key2, "measure:dnsp:%s", info->qname);
            incr(key2);
        }
    }

    sprintf(val, "%u", info->ttl);
    set_str_ex(key, val, REQ_WAIT_RESP_TIMEOUT);

    free(info);
}

// Match with the previously cached request and transfer the response into a UDP response.
void _process_dns_tcp_response(struct dns_tcp_response_info *info)
{
    char key[MAX_QNAME_LEN+100], val[100];
    int sid;

    sprintf(key, "dns:resp:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
    set_int_ex(key, 1, RESP_CACHE_TIMEOUT);

    // transfer into DNS UDP response 
    sprintf(key, "dns:req:%u_%s", info->txn_id, info->qname);
    get_str(key, val, 100);
    if (val[0] == 0) {
        log_debug("No DNS request info or DNS response has been received. %u %s", info->txn_id, info->qname);
        return;
    }

    u_int32_t saddr, daddr;
    u_int16_t sport, dport;
    sscanf(val, "%u_%hu_%u_%hu", &saddr, &sport, &daddr, &dport);

    // process 
    struct fourtuple reverse_fourtp;
    reverse_fourtp.saddr = daddr;
    reverse_fourtp.daddr = saddr;
    reverse_fourtp.sport = dport;
    reverse_fourtp.dport = sport;
    //print_fourtuple(&reverse_fourtp);

    char *payload;
    unsigned short payload_len;
    payload = info->payload + 2;
    payload_len = (((unsigned char)info->payload[0]) << 8) + (unsigned char)info->payload[1];
    
    fabricate_dns_udp_response(&reverse_fourtp, payload, payload_len);
    log_debugv("[EVAL] DNS TCP response %d", info->txn_id);

    del_key(key);

    free(info);
}

void _cache_http_request(struct http_request_info* info)
{
    char key[100], val[MAX_REQLINE_LEN];

    // waiting for response, when there are multiple concurrent requests, 
    // only cache the first unresponsed request.  
    //sprintf(key, "http:wait_resp:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
    //set_int_ex_nx(key, 1, REQ_WAIT_RESP_TIMEOUT);
    // Redis doesn't provide a timely notification event when key expires, so we set up a timer using ev_timer 
    if (prq_is_full) {
        log_error("Pending request queue is full! Request is ignored.");
        return;
    } else {
        prq[prq_tail].saddr = info->saddr;
        prq[prq_tail].daddr = info->daddr;
        prq[prq_tail].sport = info->sport;
        prq[prq_tail].dport = info->dport;
        prq[prq_tail].expire = ev_time() + timeout;
        log_debugv("Pending request: %u_%hu_%u_%hu %f", prq[prq_tail].saddr, prq[prq_tail].sport, prq[prq_tail].daddr, prq[prq_tail].dport, prq[prq_tail].expire);
        prq_tail = (prq_tail + 1) % MAX_PENDING_REQUESTS_NUM;
        if (prq_tail == prq_head) prq_is_full = 1;
        if (prq_is_empty) {
            ev_timer_set(&timer, timeout, 0);
            ev_timer_start(EV_DEFAULT_ &timer);
            prq_is_empty = 0;
        }
        log_debugv("PRQ enqueue: head=%d, tail=%d, is_empty=%d, is_full=%d", prq_head, prq_tail, prq_is_empty, prq_is_full);
    }

    // cache the last HTTP request sent in the connection 
    sprintf(key, "http:last_req:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
    sprintf(val, "%s", info->req_line);
    set_str_ex(key, val, HTTP_LAST_REQ_CACHE_TIMEOUT);

    free(info);
}

// When a HTTP resposne is received, we can learn the the connection
// is still alived, and hasn't been shutdown by our strategy. Also,
// we should cache the resposne for a short period, to see if there's
// multiple different responses from the same 4-tuple. If it happens,
// it is probably a HTTP injection attack. 
void _process_http_response(struct http_response_info* info)
{
    char key[100], val[MAX_REQLINE_LEN];
    int sid;

    // HTTP injection detection 
    sprintf(key, "http:resp:%u_%hu_%u_%hu_%u", info->saddr, info->sport, info->daddr, info->dport, info->seq);
    get_str(key, val, 100);
    if (val[0] != 0) {
        if (strtol(val, NULL, 10) != info->ttl) {
            // received two different HTTP responses from the same server
            // looks like it has been poisoned 
            if (sid == 0) {
                struct fourtuple f;
                f.saddr = info->daddr;
                f.sport = info->dport;
                f.daddr = info->saddr;
                f.dport = info->sport;
                sid = get_sid(&f);
            }

            char key2[100];
            sprintf(key2, "http:last_req:%u_%hu_%u_%hu_%u", info->daddr, info->dport, info->saddr, info->sport, info->seq);
            get_str(key2, val, MAX_REQLINE_LEN);
            if (val[0] != 0)
                log_info("[EVAL] PROBABLY HTTP INJECTION. %u_%hu_%u_%hu_%d. LAST REQ: %s", info->daddr, info->dport, info->saddr, info->sport, sid, val);
            else
                log_info("[EVAL] PROBABLY HTTP INJECTION. %u_%hu_%u_%hu_%d. LAST REQ: N/A", info->daddr, info->dport, info->saddr, info->sport, sid);
            sprintf(key2, "measure:httpi:%u:%s", info->saddr, val);
            incr(key2);
        }
    }

    set_int_ex(key, info->ttl, RESP_CACHE_TIMEOUT);

    free(info);
}

// Process incoming RST packet
// we need to decide whether it is from censor 
void _process_incoming_RST(struct tcpinfo *info)
{
    char key[100], val[MAX_REQLINE_LEN];
    int sid;

    if (info->flags == TCP_RST) {
        if (get_aflag1(info->daddr, info->saddr)) {
            free(info);
            return;
        }
        if (info->fragoff == 0 && info->win != 0) {
            struct fourtuple f;
            f.saddr = info->daddr;
            f.sport = info->dport;
            f.daddr = info->saddr;
            f.dport = info->sport;
            sid = get_sid(&f);
            sprintf(key, "http:last_req:%u_%hu_%u_%hu", info->daddr, info->dport, info->saddr, info->sport);
            get_str(key, val, MAX_REQLINE_LEN);
            log_info("Triggered Type 1 Reset! %u_%hu_%u_%hu_%d. LAST REQ: %s", info->daddr, info->dport, info->saddr, info->sport, sid, val);
            sprintf(key, "http:type1rst:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
            set_int_ex(key, 1, RESP_CACHE_TIMEOUT);
            set_aflag1(info->daddr, info->saddr);
        }
        free(info);
        return;
    }

    if (get_aflag2(info->daddr, info->saddr)) {
        free(info);
        return;
    }

    if (info->flags == TCP_RST | TCP_ACK) {
        if (info->win != 0) {

            sprintf(key, "rst:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
            // use a 32-bit int to record at most 4 TTLs 
            unsigned int ttl_set = get_int(key);
    
            if (ttl_set == 0) {
                set_int_ex(key, info->ttl, RST_CACHE_TIMEOUT);
            }
            else {
                if (is_ttl_in_set(info->ttl, ttl_set)) {
                    free(info);
                    return;
                }

                if (ttl_set > 0) {
                    // already has one TTL, 2 RST/ACK with different TTLs in a short period means a GFW type-2 reset 
                    // already has two different TTLs, 3 RST/ACK with different TTLs in a short period means a GFW type-2 reset 

                    // Triggered RST attack 
                    struct fourtuple f;
                    f.saddr = info->daddr;
                    f.sport = info->dport;
                    f.daddr = info->saddr;
                    f.dport = info->sport;
                    sid = get_sid(&f);
                    int svr_port = htons(info->sport);
                    if (svr_port == 80) {
                        sprintf(key, "http:last_req:%u_%hu_%u_%hu", info->daddr, info->dport, info->saddr, info->sport);
                        get_str(key, val, MAX_REQLINE_LEN);
                        if (val[0] != 0) {
                            log_info("Triggered Type 2 Reset! %u_%hu_%u_%hu_%d. LAST REQ: %s", info->daddr, info->dport, info->saddr, info->sport, sid, val);
                            sprintf(key, "measure:httprst:%u:%s", info->saddr, val);
                            incr(key);
                        }
                        else {
                            log_info("Triggered Type 2 Reset! %u_%hu_%u_%hu_%d. LAST REQ: N/A", info->daddr, info->dport, info->saddr, info->sport, sid);
                            sprintf(key, "measure:httprst:%u:unknown", info->saddr);
                            incr(key);
                        }
        
                        sprintf(key, "http:type2rst:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
                        set_int_ex(key, 1, RESP_CACHE_TIMEOUT);
                    }
                    else if (svr_port == 53) {
                        log_info("[EVAL] STRATEGY FAILED 2. DNS TRIGGERED RESET ATTACK. %u_%hu_%u_%hu_%d.", info->daddr, info->dport, info->saddr, info->sport, sid);
                        sprintf(key, "measure:dnsrst:%u:unknown", info->saddr);
                        incr(key);
        
                        sprintf(key, "dns:type2rst:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
                        set_int_ex(key, 1, RESP_CACHE_TIMEOUT);
                    }
        
                    set_aflag2(info->daddr, info->saddr);
                }

                // The key may has been overwritten, need to set it again.
                sprintf(key, "rst:%u_%hu_%u_%hu", info->saddr, info->sport, info->daddr, info->dport);
                ttl_set = insert_ttl(info->ttl, ttl_set);
                set_int_ex(key, ttl_set, RST_CACHE_TIMEOUT);
            }
        }
    
    }

    free(info);
}


/************************
 * Expiration callbacks *
 ************************/

void on_request_expire(const char *oldkey)
{
    char key[100];
    int sid;
    u_int32_t saddr, daddr;
    u_int16_t sport, dport;

    /*
    if (startswith(oldkey, "http:wait_resp:")) {
        sscanf(oldkey + strlen("http:wait_resp:"), "%u_%hu_%u_%hu", &saddr, &sport, &daddr, &dport);
        // if need verification?
        if (get_vflag(saddr, sport, daddr, dport)) {
            sid = get_sid(saddr, sport, daddr, dport);
            sprintf(key, "http:type1rst:%u_%hu_%u_%hu", daddr, dport, saddr, sport);
            int type1rst = get_int(key);
            sprintf(key, "http:type2rst:%u_%hu_%u_%hu", daddr, dport, saddr, sport);
            int type2rst = get_int(key);
            if (type1rst && type2rst) {
                log_info("[EVAL] STRATEGY FAILED 2. HTTP TRIGGERED BOTH TYPE 1 AND TYPE 2 RESET. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                sprintf(key, "strategy:stats:%d:%u:fail2a", sid, daddr);
                incr(key);
                sprintf(key, "strategy:stats:%d:%u:fail2b", sid, daddr);
                incr(key);
            }
            else {
                if (type1rst) {
                    log_info("[EVAL] STRATEGY FAILED 2. HTTP TRIGGERED TYPE 1 RESET. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                    sprintf(key, "strategy:stats:%d:%u:fail2a", sid, daddr);
                    incr(key);
                }
                else if (type2rst) {
                    log_info("[EVAL] STRATEGY FAILED 2. HTTP TRIGGERED TYPE 2 RESET. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                    sprintf(key, "strategy:stats:%d:%u:fail2b", sid, daddr);
                    incr(key);
                }
                else {
                    if (get_aflag1(saddr, daddr) || get_aflag2(saddr, daddr)) {
                        log_info("[EVAL] HTTP REQUEST SENT DURING 90 SEC. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                    }
                    else {
                        sprintf(key, "http:resp:%u_%hu_%u_%hu*", daddr, dport, saddr, sport);
                        if (keys_num(key) > 0) {
                            log_info("[EVAL] STRATEGY SUCCEEDED. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                            sprintf(key, "strategy:stats:%d:%u:succ", sid, daddr);
                            incr(key);
                        }
                        else {
                            // we think the lack of response of server is caused by our strategy 
                            log_info("[EVAL] STRATEGY FAILED 1. HTTP NO RESPONSE. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                            sprintf(key, "strategy:stats:%d:%u:fail1", sid, daddr);
                            incr(key);
                        }
                    }
                }
            }
            
            clear_vflag(saddr, sport, daddr, dport);
        }
    }

    if (startswith(oldkey, "dns:wait_resp:")) {
        sscanf(oldkey + strlen("dns:wait_resp:"), "%u_%hu_%u_%hu", &saddr, &sport, &daddr, &dport);
        // if need verification?
        if (get_vflag(saddr, sport, daddr, dport)) {
            sid = get_sid(saddr, sport, daddr, dport);
            sprintf(key, "http:type2rst:%u_%hu_%u_%hu", daddr, dport, saddr, sport);
            if (get_int(key)) {
                log_info("[EVAL] STRATEGY FAILED 2. DNS TRIGGERED RESET ATTACK. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                sprintf(key, "strategy:stats:%d:%u:fail2", sid, daddr);
                incr(key);

                // need to reconnect to the DNS TCP server 
                log_info("DNS triggered reset attack. Reconnecting to DNS TCP server...");
                init_dns_tcp_conn();
            }
            else {
                if (get_aflag1(saddr, daddr) || get_aflag2(saddr, daddr)) {
                    log_info("[EVAL] DNS REQUEST SENT DURING 90 SEC. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                }
                else {
                    sprintf(key, "dns:resp:%u_%hu_%u_%hu*", daddr, dport, saddr, sport);
                    if (keys_num(key) > 0) {
                        log_info("[EVAL] STRATEGY SUCCEEDED. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                        sprintf(key, "strategy:stats:%d:%u:succ", sid, daddr);
                        incr(key);
                    }
                    else {
                        // we think the lack of response of server is caused by our strategy 
                        log_info("[EVAL] STRATEGY FAILED 1. DNS NO RESPONSE. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                        sprintf(key, "strategy:stats:%d:%u:fail1", sid, daddr);
                        incr(key);

                        // need to reconnect to the DNS TCP server 
                        log_info("DNS TCP request timeout. Reconnecting to DNS TCP server...");
                        init_dns_tcp_conn();
                    }
                }
            }
            
            clear_vflag(saddr, sport, daddr, dport);
        }
    }
    */
}


/*********************
 * EV Timer Callback *
 *********************/

static void process_timeout(struct pending_request *pr) {
    char key[100];
    int sid;
    u_int32_t saddr, daddr;
    u_int16_t sport, dport;
    saddr = pr->saddr;
    daddr = pr->daddr;
    sport = pr->sport;
    dport = pr->dport;

    if (dport == 20480) { // port 80
        // if need verification?
        if (get_vflag(saddr, sport, daddr, dport)) {
            struct fourtuple f;
            f.saddr = saddr;
            f.sport = sport;
            f.daddr = daddr;
            f.dport = dport;
            sid = get_sid(&f);
            sprintf(key, "http:type1rst:%u_%hu_%u_%hu", daddr, dport, saddr, sport);
            int type1rst = get_int(key);
            sprintf(key, "http:type2rst:%u_%hu_%u_%hu", daddr, dport, saddr, sport);
            int type2rst = get_int(key);
            if (type1rst && type2rst) {
                log_info("[EVAL] STRATEGY FAILED 2. HTTP TRIGGERED BOTH TYPE 1 AND TYPE 2 RESET. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                sprintf(key, "strategy:stats:%d:%u:fail2a", sid, daddr);
                incr(key);
                sprintf(key, "strategy:stats:%d:%u:fail2b", sid, daddr);
                incr(key);
                incr_fail2(daddr, sid);
                // increase TTL if necessary. if we used TTL as discrepancy, we should increase the TTL; 
                // otherwise, we can also increase it safely.
                incr_ttl(daddr);
            }
            else {
                if (type1rst) {
                    log_info("[EVAL] STRATEGY FAILED 2. HTTP TRIGGERED TYPE 1 RESET. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                    sprintf(key, "strategy:stats:%d:%u:fail2a", sid, daddr);
                    incr(key);
                    incr_fail2(daddr, sid);
                    // increase TTL if necessary
                    incr_ttl(daddr);
                }
                else if (type2rst) {
                    log_info("[EVAL] STRATEGY FAILED 2. HTTP TRIGGERED TYPE 2 RESET. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                    sprintf(key, "strategy:stats:%d:%u:fail2b", sid, daddr);
                    incr(key);
                    incr_fail2(daddr, sid);
                    // increase TTL if necessary
                    incr_ttl(daddr);
                }
                else {
                    if (get_aflag1(saddr, daddr) || get_aflag2(saddr, daddr)) {
                        log_info("[EVAL] HTTP REQUEST SENT DURING 90 SEC. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                    }
                    else {
                        sprintf(key, "http:resp:%u_%hu_%u_%hu*", daddr, dport, saddr, sport);
                        if (keys_num(key) > 0) {
                            log_info("[EVAL] STRATEGY SUCCEEDED. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                            sprintf(key, "strategy:stats:%d:%u:succ", sid, daddr);
                            incr(key);
                            incr_succ(daddr, sid);
                        }
                        else {
                            // we think the lack of response of server is caused by our strategy
                            log_info("[EVAL] STRATEGY FAILED 1. HTTP NO RESPONSE. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                            sprintf(key, "strategy:stats:%d:%u:fail1", sid, daddr);
                            incr(key);
                            incr_fail1(daddr, sid);
                            // decrease TTL if necessary. if the failure 1 is caused by our insertion packets, 
                            // we should decrease the TTL.
                            decr_ttl(daddr);
                        }
                    }
                }
            }
            
            clear_vflag(saddr, sport, daddr, dport);
            set_verified(saddr, sport, daddr, dport);
        }
    }

    if (dport == 13568) { // port 53
        // if need verification?
        if (get_vflag(saddr, sport, daddr, dport)) {
            struct fourtuple f;
            f.saddr = saddr;
            f.sport = sport;
            f.daddr = daddr;
            f.dport = dport;
            sid = get_sid(&f);
            sprintf(key, "http:type2rst:%u_%hu_%u_%hu", daddr, dport, saddr, sport);
            if (get_int(key)) {
                log_info("[EVAL] STRATEGY FAILED 2. DNS TRIGGERED RESET ATTACK. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                sprintf(key, "strategy:stats:%d:%u:fail2", sid, daddr);
                incr(key);
                incr_fail2(daddr, sid);

                // need to reconnect to the DNS TCP server
                log_info("DNS triggered reset attack. Reconnecting to DNS TCP server...");
                init_dns_tcp_conn();
            }
            else {
                if (get_aflag1(saddr, daddr) || get_aflag2(saddr, daddr)) {
                    log_info("[EVAL] DNS REQUEST SENT DURING 90 SEC. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                }
                else {
                    sprintf(key, "dns:resp:%u_%hu_%u_%hu*", daddr, dport, saddr, sport);
                    if (keys_num(key) > 0) {
                        log_info("[EVAL] STRATEGY SUCCEEDED. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                        sprintf(key, "strategy:stats:%d:%u:succ", sid, daddr);
                        incr(key);
                        incr_succ(daddr, sid);
                    }
                    else {
                        // we think the lack of response of server is caused by our strategy
                        log_info("[EVAL] STRATEGY FAILED 1. DNS NO RESPONSE. %u_%hu_%u_%hu_%d", saddr, sport, daddr, dport, sid);
                        sprintf(key, "strategy:stats:%d:%u:fail1", sid, daddr);
                        incr(key);
                        incr_fail1(daddr, sid);

                        // need to reconnect to the DNS TCP server
                        log_info("DNS TCP request timeout. Reconnecting to DNS TCP server...");
                        init_dns_tcp_conn();
                    }
                }
            }
            
            clear_vflag(saddr, sport, daddr, dport);
            set_verified(saddr, sport, daddr, dport);
        }
    }
}

static void ev_timer_cb(EV_P_ ev_timer *w, int revents)
{
    ev_tstamp now;
    log_debugv("PRQ Timeout.");
    log_debugv("PRQ dequeue: head=%d, tail=%d, is_empty=%d, is_full=%d", prq_head, prq_tail, prq_is_empty, prq_is_full);
    while (prq[prq_head].expire - ev_time() < 0.2 && !prq_is_empty) {
        struct pending_request *pr = &prq[prq_head];
        log_debug("Pending request expired. %u_%hu_%u_%hu %f", pr->saddr, pr->sport, pr->daddr, pr->dport, pr->expire);
        process_timeout(pr);
        prq_head = (prq_head + 1) % MAX_PENDING_REQUESTS_NUM;
        if (prq_head == prq_tail) prq_is_empty = 1;
        prq_is_full = 0;
        log_debugv("PRQ dequeue: head=%d, tail=%d, is_empty=%d, is_full=%d", prq_head, prq_tail, prq_is_empty, prq_is_full);
    }

    if (!prq_is_empty) {
        ev_tstamp to = prq[prq_head].expire - ev_time();
        ev_timer_set(&timer, to, 0);
        ev_timer_start(EV_DEFAULT_ &timer);
    }
}


static void order_cb(EV_P_ ev_async *w, int revents)
{
    int type;
    void *data;

    log_debugv("order_cb");

    while ((type = get_order(&data)) != 0) {
        switch (type) {
            case ORDER_CACHE_DNS_UDP_REQUEST:
                log_debugv("ORDER_CACHE_DNS_UDP_REQUEST");
                _cache_dns_udp_request(data);
                break;
            case ORDER_CACHE_DNS_TCP_REQUEST:
                log_debugv("ORDER_CACHE_DNS_TCP_REQUEST");
                _cache_dns_tcp_request(data);
                break;
            case ORDER_PROC_DNS_UDP_RESPONSE:
                log_debugv("ORDER_PROC_DNS_UDP_RESPONSE");
                _process_dns_udp_response(data);
                break;
            case ORDER_PROC_DNS_TCP_RESPONSE:
                log_debugv("ORDER_PROC_DNS_TCP_RESPONSE");
                _process_dns_tcp_response(data);
                break;
            case ORDER_CACHE_HTTP_REQUEST:
                log_debugv("ORDER_CACHE_HTTP_REQUEST");
                _cache_http_request(data);
                break;
            case ORDER_PROC_HTTP_RESPONSE:
                log_debugv("ORDER_PROC_HTTP_RESPONSE");
                _process_http_response(data);
                break;
            case ORDER_PROC_INCOMING_RST:
                log_debugv("ORDER_PROC_INCOMING_RST");
                _process_incoming_RST(data);
                break;
            case ORDER_CACHE_STRATEGY:
                log_debugv("ORDER_CACHE_STRATEGY");
                _cache_strategy(data);
                break;
            case ORDER_NEED_EVAL:
                log_debugv("ORDER_NEED_EVAL");
                _need_evaluation(data);
                break;
            case ORDER_REMOVE_VFLAG:
                log_debugv("ORDER_REMOVE_VFLAG");
                _remove_vflag(data);
                break;
            default:
                break;
        }
    }

    log_debugv("order_cb_end");
}


// main function 
int cache_main_loop()
{
    connect_to_redis();

    load_historical_result_from_redis();
    load_ttl_from_redis();

    ev_loop(EV_DEFAULT_ 0);

    return 0;
}



