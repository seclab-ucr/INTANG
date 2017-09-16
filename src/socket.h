
#ifndef __SOCKET_H__
#define __SOCKET_H__

#define TCP_SYN (1 << 1)
#define TCP_ACK (1 << 4)
#define TCP_RST (1 << 2)
#define TCP_FIN 1
#define TCP_PSH (1 << 3)
#define TCP_URG (1 << 5)

#define MAX_PACKET_SIZE 4096
#define DEFAULT_TTL 128
#define DEFAULT_WINDOW_SIZE 29200

#define DNS_PORT_NUM 53


struct send_tcp_vars {
    // ip layer
    char src_ip[16]; // required
    char dst_ip[16]; // required
    unsigned char ttl;
    unsigned short ipid;
    // tcp layer
    unsigned short src_port; // required
    unsigned short dst_port; // required
    unsigned int seq_num; // required
    unsigned int ack_num;
    unsigned char wrong_tcp_checksum;
    unsigned char wrong_tcp_doff;
    unsigned char wrong_ip_tot_len;
    unsigned char flags; // required
    unsigned short win_size;
    unsigned char has_timestamp;
    char tcp_opt[40]; // max tcp option size is 40
    unsigned char tcp_opt_len;
    // tcp payload
    char payload[4096];
    unsigned short payload_len;
};

struct send_udp_vars {
    // ip layer
    char src_ip[16]; // required
    char dst_ip[16]; // required
    unsigned char ttl;
    unsigned short ipid;
    // udp layer
    unsigned short src_port; // required
    unsigned short dst_port; // required
    // udp payload
    char payload[4096];
    unsigned short payload_len;
};

struct send_dns_vars {
    // ip layer
    char src_ip[16]; // required
    char dst_ip[16]; // required
    // udp layer
    unsigned short src_port; // required
    unsigned short dst_port; 
    // dns proto
    char domain[64]; // required
    unsigned short txn_id;
};

int init_socket();

void send_raw(unsigned char *pkt, unsigned int len);
void send_tcp(struct send_tcp_vars *vars);
void send_udp(struct send_udp_vars *vars);

struct mypacket;
void send_udp2(struct mypacket *packet);

void send_SYN(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num
);
void send_SYN_ACK(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num
);
void send_ACK(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num
);
void send_ACK_with_one_ttl(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num
);
void send_one_ttl_SYN(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num
);
void send_one_ttl_SYN_and_SYN_ACK(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num
);

void send_ip_fragment(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num,
        unsigned short ipid, unsigned short fragoff, 
        unsigned short frag_len, unsigned char more_fragments,
        char *payload, unsigned short payload_len
);


#endif


