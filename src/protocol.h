
#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>

#define MAX_QNAME_LEN 64

#define MAX_REQLINE_LEN 1000

/*
 * IP header
 */
struct myiphdr {
    u_int8_t    ihl:4,
                version:4;
    u_int8_t    tos;
    u_int16_t   tot_len;
    u_int16_t   id;
    u_int16_t   frag_off;
    u_int8_t    ttl;
    u_int8_t    protocol;
    u_int16_t   check;
    u_int32_t   saddr;
    u_int32_t   daddr;
};

/*
 * IPv6 header
 */
struct myipv6hdr {
    u_int32_t	version:4,
		traffic_class:8,
		flow_label:20;
    u_int16_t	payload_len;
    u_int8_t	protocol;
    u_int8_t	ttl;
    u_int32_t	saddr[4];
    u_int32_t   daddr[4];
};

/*
 * UDP header
 */
struct myudphdr { 
    u_int16_t uh_sport;     /* source port */
    u_int16_t uh_dport;     /* destination port */
    u_int16_t uh_ulen;      /* udp length */
    u_int16_t uh_sum;       /* udp checksum */
};

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct mytcphdr {
    u_int16_t	th_sport;               /* source port */
    u_int16_t	th_dport;               /* destination port */
    u_int32_t	th_seq;                 /* sequence number */
    u_int32_t	th_ack;                 /* acknowledgement number */
    u_int8_t    th_x2:4,                /* (unused) */
                th_off:4;               /* data offset */
    u_int8_t    th_flags;
    u_int16_t   th_win;                 /* window */
    u_int16_t   th_sum;                 /* checksum */
    u_int16_t   th_urp;                 /* urgent pointer */
};

/*
 * UDP/TCP pseudo header
 * for cksum computing
 */
struct pseudohdr
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t  zero;
    u_int8_t  protocol;
    u_int16_t length;
};

/*
 * DNS header
 */

struct mydnsquery
{
    char qname[100];
    u_int16_t qtype;
    u_int16_t qclass;
};

struct mydnshdr
{
    u_int16_t txn_id;
    u_int16_t flags;
    u_int16_t questions;
    u_int16_t answer_rrs;
    u_int16_t authority_rrs;
    u_int16_t addtional_rrs;
};

struct fourtuple
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
};

struct mypacket
{
    unsigned char *data;
    unsigned int len;
    struct myiphdr *iphdr;  // layer 3 IP header
    union {
        struct mytcphdr *tcphdr;    // layer 4 TCP header
        struct myudphdr *udphdr;    // layer 4 UDP header
    };
    unsigned char *payload; // layer 4 payload
    unsigned int payload_len;
};

struct tcpinfo
{
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
    u_int16_t dport;
    u_int8_t flags;
    u_int32_t seq;
    u_int32_t ack;
    u_int8_t ttl;
    u_int16_t win;
    u_int16_t fragoff;
};


static inline struct myiphdr* ip_hdr(unsigned char *pkt_data)
{
    return (struct myiphdr*)pkt_data;
}

static inline struct mytcphdr* tcp_hdr(unsigned char *pkt_data)
{
    return (struct mytcphdr*)(pkt_data+ip_hdr(pkt_data)->ihl*4);
}

static inline unsigned char* tcp_payload(unsigned char *pkt_data)
{
    return pkt_data+ip_hdr(pkt_data)->ihl*4+tcp_hdr(pkt_data)->th_off*4;
}

static inline unsigned char* udp_payload(unsigned char *pkt_data)
{
    return pkt_data+ip_hdr(pkt_data)->ihl*4+8;
}

static inline struct myudphdr* udp_hdr(unsigned char *pkt_data)
{
    return (struct myudphdr*)(pkt_data+((struct myiphdr*)pkt_data)->ihl*4);
}

// for 6-in-4 tunnel
static inline struct myipv6hdr* ipv6_hdr_6in4(unsigned char *pkt_data)
{
    return (struct myipv6hdr*)(pkt_data+ip_hdr(pkt_data)->ihl*4);
}

static inline struct mytcphdr* tcp_hdr_6in4(unsigned char *pkt_data)
{
    return NULL;
}

static inline unsigned char* tcp_payload_6in4(unsigned char *pkt_data)
{
    return NULL;
}


#endif

