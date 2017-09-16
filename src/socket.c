
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

#include "globals.h"
#include "socket.h"
#include "protocol.h"
#include "logging.h"
#include "helper.h"


static int raw_sock;


int init_socket()
{
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock == -1) {
        log_error("failed to create raw socket.");
        return -1;
    }
    /* setting socket option to use MARK value */
    int mark = MARK;
    if (setsockopt(raw_sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
    {
        log_error("failed to set mark on raw socket.");
        return -1;
    } 
    return 0;
}

int close_socket()
{
    if (raw_sock)
        close(raw_sock);
    return 0;
}

u_int16_t ip_checksum(char *packet, int len)
{
    struct myiphdr *iphdr = (struct myiphdr*)packet;
    int iphdr_len = iphdr->ihl << 2;

    // set ip checksum to zero
    iphdr->check = 0;

    u_int16_t *buf = (u_int16_t*)packet;
    int nbytes = iphdr_len;

    u_int32_t sum;

    sum = 0;
    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        sum += *((u_int8_t*)buf);
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (u_int16_t) ~sum;
}

u_int16_t tcp_checksum(char *packet, int len)
{
    struct myiphdr *iphdr = (struct myiphdr*)packet;
    int iphdr_len = iphdr->ihl << 2;
    struct mytcphdr *tcphdr = (struct mytcphdr*)(packet + iphdr_len);
    int tcphdr_len = tcphdr->th_off << 2;
    int payload_len = len - iphdr_len - tcphdr_len;

    // set tcp checksum to zero
    tcphdr->th_sum = 0;

    // calculate checksum
    int ppkt_size = sizeof(struct pseudohdr) + tcphdr_len + payload_len;
    char *ppkt = (char*)malloc(ppkt_size);
    struct pseudohdr *phdr = (struct pseudohdr*)ppkt;
    phdr->saddr = iphdr->saddr;
    phdr->daddr = iphdr->daddr;
    phdr->zero = 0;
    phdr->protocol = 6; // tcp
    phdr->length = htons(tcphdr_len + payload_len);
    memcpy(ppkt + sizeof(struct pseudohdr), packet + iphdr_len, tcphdr_len + payload_len);

    u_int16_t *buf = (u_int16_t*)ppkt;
    int nbytes = ppkt_size;

    u_int32_t sum;

    sum = 0;
    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        sum += *((u_int8_t*)buf);
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    free(ppkt);
    return (u_int16_t) ~sum;
}

u_int16_t udp_checksum(char *packet, int len)
{
    struct myiphdr *iphdr = (struct myiphdr*)packet;
    int iphdr_len = iphdr->ihl << 2;
    struct myudphdr *udphdr = (struct myudphdr*)(packet + iphdr_len);
    int udphdr_len = 8;
    int payload_len = len - iphdr_len - udphdr_len;

    // set udp checksum to zero
    udphdr->uh_sum = 0;

    // calculate checksum
    int ppkt_size = sizeof(struct pseudohdr) + udphdr_len + payload_len;
    char *ppkt = (char*)malloc(ppkt_size);
    struct pseudohdr *phdr = (struct pseudohdr*)ppkt;
    phdr->saddr = iphdr->saddr;
    phdr->daddr = iphdr->daddr;
    phdr->zero = 0;
    phdr->protocol = 17; // udp
    phdr->length = htons(udphdr_len + payload_len);
    memcpy(ppkt + sizeof(struct pseudohdr), packet + iphdr_len, udphdr_len + payload_len);

    u_int16_t *buf = (u_int16_t*)ppkt;
    int nbytes = ppkt_size;

    u_int32_t sum;

    sum = 0;
    while (nbytes > 1) {
        sum += *buf++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        sum += *((u_int8_t*)buf);
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    free(ppkt);
    return (u_int16_t) ~sum;
}

void send_raw(unsigned char *pkt, unsigned int len)
{
    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = tcp_hdr(pkt)->th_dport;
    dst_addr.sin_addr.s_addr = ip_hdr(pkt)->daddr;
    int ret = sendto(raw_sock, pkt, len, 0, (struct sockaddr*)&dst_addr, sizeof dst_addr);
    //hex_dump(pkt, len);
    if (ret < 0) {
        log_error("send_raw: sendto() failed.");
    }
    else {
        //log_debug("Packet sent. total: %d, sent: %d.", tot_len, ret);
    }
}

void send_tcp(struct send_tcp_vars *vars)
{
    char packet[MAX_PACKET_SIZE];
    memset(packet, 0, MAX_PACKET_SIZE);

    struct myiphdr *iphdr = (struct myiphdr*)packet;
    int iphdr_len = 20;

    iphdr->version = 4;
    iphdr->ihl = iphdr_len >> 2;
    iphdr->tos = 0;
    iphdr->id = vars->ipid ? 
        htons(vars->ipid) : 
        htons((unsigned short)rand());
    iphdr->frag_off = 0x0040; // don't fragment
    iphdr->ttl = vars->ttl ? 
        vars->ttl : 
        DEFAULT_TTL;
    iphdr->protocol = 6; // tcp
    // checksum will be filled automatically
    iphdr->saddr = str2ip(vars->src_ip);
    iphdr->daddr = str2ip(vars->dst_ip);
    
    struct mytcphdr *tcphdr = (struct mytcphdr*)(packet + iphdr_len);
    int tcphdr_len = 20;
    
    tcphdr->th_sport = htons(vars->src_port);
    tcphdr->th_dport = htons(vars->dst_port);
    tcphdr->th_seq = htonl(vars->seq_num);
    tcphdr->th_ack = htonl(vars->ack_num);
    tcphdr->th_off = tcphdr_len >> 2;
    tcphdr->th_flags = vars->flags;
    tcphdr->th_win = vars->win_size ?
        htons(vars->win_size) :
        htons(DEFAULT_WINDOW_SIZE);

    if (vars->tcp_opt_len) {
        memcpy(packet+iphdr_len+tcphdr_len, vars->tcp_opt, vars->tcp_opt_len);
        tcphdr_len += vars->tcp_opt_len;
        tcphdr_len = (tcphdr_len + 3) / 4 * 4; // round up to multiple of 4
        tcphdr->th_off = tcphdr_len / 4; // update data offset
    }

    if (vars->wrong_tcp_doff) {
        tcphdr->th_off = 4;
    }

    // calculate size
    int payload_len = vars->payload_len;
    if (payload_len) {
        memcpy(packet+iphdr_len+tcphdr_len, vars->payload, payload_len);
    }
    int tot_len = iphdr_len + tcphdr_len + payload_len;
    iphdr->tot_len = htons(tot_len);

    if (vars->wrong_ip_tot_len) {
        iphdr->tot_len += 16;
        /* seems not working! dunno why */
    }

    // calculate checksum
    tcphdr->th_sum = tcp_checksum(packet, tot_len);
    if (vars->wrong_tcp_checksum)
        tcphdr->th_sum ^= 13524;

    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = tcphdr->th_dport;
    dst_addr.sin_addr.s_addr = iphdr->daddr;
    int ret = sendto(raw_sock, packet, tot_len, 0, (struct sockaddr*)&dst_addr, sizeof dst_addr);
    //hex_dump(packet, tot_len);
    if (ret < 0) {
        log_error("send_tcp: sendto() failed.");
    }
    else {
        //log_debug("Packet sent. total: %d, sent: %d.", tot_len, ret);
    }
}


void send_udp(struct send_udp_vars *vars)
{
    char packet[MAX_PACKET_SIZE];
    memset(packet, 0, MAX_PACKET_SIZE);

    struct myiphdr *iphdr = (struct myiphdr*)packet;
    int iphdr_len = 20;

    iphdr->version = 4;
    iphdr->ihl = iphdr_len >> 2;
    iphdr->tos = 0;
    iphdr->id = vars->ipid ? 
        htons(vars->ipid) : 
        htons((unsigned short)rand());
    iphdr->frag_off = 0x0040; // don't fragment
    iphdr->ttl = vars->ttl ? 
        vars->ttl : 
        DEFAULT_TTL;
    iphdr->protocol = 17; // udp
    // checksum will be filled automatically
    iphdr->saddr = str2ip(vars->src_ip);
    iphdr->daddr = str2ip(vars->dst_ip);

    struct myudphdr *udphdr = (struct myudphdr*)(packet + iphdr_len);
    int udphdr_len = 8;
    
    udphdr->uh_sport = htons(vars->src_port);
    udphdr->uh_dport = htons(vars->dst_port);
    udphdr->uh_ulen = htons(udphdr_len);
    udphdr->uh_sum = 0;

    // calculate size
    int payload_len = vars->payload_len;
    if (payload_len) {
        udphdr->uh_ulen = htons(udphdr_len + payload_len);
        memcpy(packet+iphdr_len+udphdr_len, vars->payload, payload_len);
    }
    int tot_len = iphdr_len + udphdr_len + payload_len;
    iphdr->tot_len = htons(tot_len);

    // calculate checksum
    //udphdr->uh_sum = udp_checksum(packet, tot_len);

    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = udphdr->uh_dport;
    dst_addr.sin_addr.s_addr = iphdr->daddr;
    int ret = sendto(raw_sock, packet, tot_len, 0, (struct sockaddr*)&dst_addr, sizeof dst_addr);
    //hex_dump(packet, tot_len);
    if (ret < 0) {
        log_error("send_udp: sendto() failed.");
    }
    else {
        //log_debug("Packet sent. total: %d, sent: %d.", tot_len, ret);
    }
}

void send_udp2(struct mypacket *packet)
{
    int ret;
    char pkt[MAX_PACKET_SIZE];
    int tot_len = 0;
    int iphdr_len = 20;
    int udphdr_len = 8;
    struct myiphdr *iphdr = (struct myiphdr*)pkt;
    struct myudphdr *udphdr = (struct myudphdr*)(pkt + iphdr_len);

    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = packet->udphdr->uh_dport;
    dst_addr.sin_addr.s_addr = packet->iphdr->daddr;

    int cut_pos = 10;
    
    tot_len = iphdr_len + udphdr_len + cut_pos;
    memcpy(pkt, packet->data, tot_len);
    udphdr = (struct myudphdr*)(pkt + iphdr_len);
    udphdr->uh_ulen = udphdr_len + cut_pos;

    ret = sendto(raw_sock, pkt, tot_len, 0, (struct sockaddr*)&dst_addr, sizeof dst_addr);
    //hex_dump(packet, tot_len);
    if (ret < 0) {
        log_error("send_udp2: sendto() failed.");
    }
    else {
        log_debug("Packet split #1 sent. total: %d, sent: %d.", tot_len, ret);
    }

    tot_len = iphdr_len + udphdr_len + packet->payload_len - cut_pos;
    memcpy(pkt + iphdr_len + udphdr_len, packet->data + cut_pos, packet->payload_len - cut_pos);
    udphdr->uh_ulen = udphdr_len + packet->payload_len - cut_pos;

    iphdr->id = htons((unsigned short)rand());

    ret = sendto(raw_sock, pkt, tot_len, 0, (struct sockaddr*)&dst_addr, sizeof dst_addr);
    //hex_dump(packet, tot_len);
    if (ret < 0) {
        log_error("send_udp2: sendto() failed.");
    }
    else {
        log_debug("Packet split #2 sent. total: %d, sent: %d.", tot_len, ret);
    }
}

void send_SYN(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num)
{
    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_SYN;
    vars.seq_num = seq_num;
    vars.ack_num = 0;
    //vars.wrong_tcp_checksum = 1;

    // mss
    u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    memcpy(vars.tcp_opt, bytes, 4);
    vars.tcp_opt_len = 4;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

void send_SYN_ACK(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num)
{
    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_SYN | TCP_ACK;
    vars.seq_num = seq_num;
    vars.ack_num = ack_num;
    //vars.wrong_tcp_checksum = 1;

    // mss
    u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    memcpy(vars.tcp_opt, bytes, 4);
    vars.tcp_opt_len = 4;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

void send_ACK(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num)
{
    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_ACK;
    vars.seq_num = seq_num;
    vars.ack_num = ack_num;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

void send_ACK_with_one_ttl(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_ACK;
    vars.seq_num = seq_num;
    vars.ack_num = ack_num;
    vars.ttl = 1;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

void send_one_ttl_SYN(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_SYN;
    vars.seq_num = htonl(ntohl(seq_num)-1);
    vars.ack_num = 0;
    vars.ttl = 1;

    // mss
    u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    memcpy(vars.tcp_opt, bytes, 4);
    vars.tcp_opt_len = 4;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

void send_one_ttl_SYN_and_SYN_ACK(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_SYN;
    vars.seq_num = htonl(ntohl(seq_num)-1);
    vars.ack_num = ack_num;
    vars.ttl = 1;

    // mss
    u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    memcpy(vars.tcp_opt, bytes, 4);
    vars.tcp_opt_len = 4;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);

    strncpy(vars.src_ip, dst_ip, 16);
    strncpy(vars.dst_ip, NAT_EXT_IP, 16);
    vars.src_port = dst_port;
    vars.dst_port = src_port;
    vars.flags = TCP_SYN | TCP_ACK;
    vars.seq_num = ack_num;
    vars.ack_num = seq_num;
    vars.ttl = 1;

    // mss
    memcpy(vars.tcp_opt, bytes, 4);
    vars.tcp_opt_len = 4;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

void send_ip_fragment(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num,
        unsigned short ipid, unsigned short fragoff, 
        unsigned short frag_len, unsigned char more_fragments,
        char *payload, unsigned short payload_len)
{
    char packet[MAX_PACKET_SIZE];
    memset(packet, 0, MAX_PACKET_SIZE);

    struct myiphdr *iphdr = (struct myiphdr*)packet;
    int iphdr_len = 20;

    iphdr->version = 4;
    iphdr->ihl = iphdr_len >> 2;
    iphdr->tos = 0;
    iphdr->id = htons(ipid);
    //iphdr->frag_off = 0x0040; // don't fragment
    iphdr->frag_off = htons((more_fragments << 13) + (fragoff >> 3));
    iphdr->ttl = DEFAULT_TTL;
    iphdr->protocol = 6; // tcp
    // checksum will be filled automatically
    iphdr->saddr = str2ip(src_ip);
    iphdr->daddr = str2ip(dst_ip);
    
    int tot_len;
    if (fragoff == 0) {
        // first packet, make tcp header
        struct mytcphdr *tcphdr = (struct mytcphdr*)(packet + iphdr_len);
        int tcphdr_len = 20;
    
        tcphdr->th_sport = htons(src_port);
        tcphdr->th_dport = htons(dst_port);
        tcphdr->th_seq = seq_num;
        tcphdr->th_ack = ack_num;
        tcphdr->th_off = tcphdr_len >> 2;
        tcphdr->th_flags = TCP_ACK;
        tcphdr->th_win = htons(DEFAULT_WINDOW_SIZE);

        char tcp_opt[40];
        unsigned char tcp_opt_len = 0;
        if (tcp_opt_len) {
            memcpy(packet+iphdr_len+tcphdr_len, tcp_opt, tcp_opt_len);
            tcphdr_len += tcp_opt_len;
            tcphdr_len = (tcphdr_len + 3) / 4 * 4; // round up to multiple of 4
            tcphdr->th_off = tcphdr_len / 4; // update data offset
        }

        if (payload_len) {
            // still need to copy the entire payload to calculate tcp checksum
            memcpy(packet+iphdr_len+tcphdr_len, payload, payload_len);
        }
        tot_len = iphdr_len + frag_len;
        iphdr->tot_len = htons(tot_len);

        // calculate checksum
        tcphdr->th_sum = tcp_checksum(packet, iphdr_len + tcphdr_len + payload_len);
        //if (vars->wrong_tcp_checksum)
        //    tcphdr->th_sum ^= 13524;
    } 
    else {
        int tcphdr_len = 20;
        
        tot_len = iphdr_len + frag_len; //payload_len;
        iphdr->tot_len = htons(tot_len);

        if (payload_len) {
            memcpy(packet+iphdr_len, payload+fragoff-tcphdr_len, frag_len);
        }
    }


    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dst_port);
    dst_addr.sin_addr.s_addr = iphdr->daddr;
    int ret = sendto(raw_sock, packet, tot_len, 0, (struct sockaddr*)&dst_addr, sizeof dst_addr);
    //hex_dump(packet, tot_len);
    if (ret < 0) {
        log_error("send_tcp: sendto() failed. errno: %d", errno);
    }
    else {
        //log_debug("Packet sent. total: %d, sent: %d.", tot_len, ret);
    }
}


