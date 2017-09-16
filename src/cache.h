
#ifndef __CACHE_H__
#define __CACHE_H__

#include <time.h>

#include "protocol.h"


// Wait for requests and responses for 30 seconds to verify the state of the conneciton. If there's no requests and responses within 30 seconds, give up the verification 
#define STRATEGY_VERIFICATION_TIMEOUT 30

// A response must be received after sending a request, otherwise we think it's our strategy shutdown the connection 
#define REQ_WAIT_RESP_TIMEOUT 5

// Cache the 4-tuple of DNS UDP request 
#define DNS_UDP_REQ_CACHE_TIMEOUT 5

// Cache the last HTTP request sent in a connection 
#define HTTP_LAST_REQ_CACHE_TIMEOUT 10

// Cache the response, when wait_resp timeouts, it will check
// if there's any response in cache. So RESP_CACHE_TIMEOUT 
// must be greater than REQ_WAIT_RESP_TIMEOUT 
#define RESP_CACHE_TIMEOUT 10

// Interval between two RST packets in a RST injection attack 
#define RST_CACHE_TIMEOUT 2

// The confinement period after a RST attack is triggered 
#define RST_ATTACK_TIMEOUT 90

// four tuple will only be verified once during 60 seconds 
#define STRATEGY_VERIFIED_TIMEOUT 60


/**************************************
 * Function calls for the main thread *
 **************************************/

void init_ev_watchers();

void need_evaluation(
    const struct fourtuple *fourtp
);

void cache_strategy(
    const struct fourtuple *fourtp, 
    int sid
);

void 
cache_dns_udp_request(
    unsigned short txn_id, 
    const char *qname, 
    const struct fourtuple *fourtp
);

void 
cache_dns_tcp_request(
    const struct fourtuple *fourtp
);

void 
process_dns_udp_response(
    unsigned short txn_id, 
    const char *qname, 
    const struct fourtuple *fourtp, 
    unsigned char ttl
);

void 
process_dns_tcp_response(
    unsigned short txn_id, 
    const char *qname, 
    const struct fourtuple *fourtp, 
    unsigned int seq,
    unsigned char ttl,
    const unsigned char *payload, 
    unsigned short payload_len
);

void 
cache_http_request(
    const struct fourtuple *fourtp, 
    const char *req_line
);

void 
process_http_response(
    const struct fourtuple *fourtp, 
    unsigned int seq,
    unsigned char ttl
);

void process_incoming_RST(
    const struct mypacket *packet
);


void on_request_expire(const char *oldkey);


int cache_main_loop();


#endif

