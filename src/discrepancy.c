
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "discrepancy.h"
#include "helper.h"
#include "ttl_probing.h"


void send_insertion_packet(struct send_tcp_vars *vars, unsigned int flags)
{
    if (flags & INS_DISC_SMALL_TTL) {
        unsigned char ttl = get_ttl(str2ip(vars->dst_ip));
        vars->ttl = ttl - 3;
    }

    if (flags & INS_DISC_BAD_TCP_CHECKSUM) {
        vars->wrong_tcp_checksum = 1;
    }

    if (flags & INS_DISC_NO_TCP_FLAG) {
        // this will override existing flags
        vars->flags = 0;
    }

    if (flags & INS_DISC_BAD_ACK_NUM) {
        // ack number in the future, is it good for all cases?
        vars->ack_num + 100000;
    }

    if (flags & INS_DISC_MD5) {
        u_char bytes[20] = {0x13,0x12,0xf9,0x89,0x5c,0xdd,0xa6,0x15,0x12,0x83,0x3e,0x93,0x11,0x22,0x33,0x44,0x55,0x66,0x01,0x01};
        memcpy(vars->tcp_opt + vars->tcp_opt_len, bytes, 20);
        vars->tcp_opt_len += 20;
    }

    if (flags & INS_DISC_OLD_TIMESTAMP) {
        // check if there's timestamp 
        int i;
        for (i = 0; i < vars->tcp_opt_len; i++) {
            unsigned char kind = vars->tcp_opt[i];
            if (kind == 1) continue;  // padding
            unsigned char len = vars->tcp_opt[i + 1];
            if (kind == 8) // Timestamp
            {
                unsigned int *tsval = (unsigned int*)(vars->tcp_opt + i + 2);
                *tsval = htonl(ntohl(*tsval) - 10000);
                break;
            }
            else 
            {
                i += len;
            }
        }
    }

    //dump_send_tcp_vars(vars);

    send_tcp(vars);
}

void send_fake_SYN(struct mypacket *orig_packet, unsigned int flags) 
{
    char sip[16], dip[16];
    unsigned short sport, dport;
    unsigned int seq_num, ack_num;
    struct send_tcp_vars vars = {};

    struct in_addr s_in_addr = {orig_packet->iphdr->saddr};
    struct in_addr d_in_addr = {orig_packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(orig_packet->tcphdr->th_sport);
    dport = ntohs(orig_packet->tcphdr->th_dport);
    seq_num = ntohl(orig_packet->tcphdr->th_seq);
    ack_num = ntohl(orig_packet->tcphdr->th_ack);

    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, sip, 16);
    strncpy(vars.dst_ip, dip, 16);
    vars.src_port = sport;
    vars.dst_port = dport;
    vars.flags = TCP_SYN;
    vars.seq_num = seq_num - 100000;
    vars.ack_num = 0;

    // mss (aliyun discards SYN without mss option header)
    //u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    //memcpy(vars.tcp_opt, bytes, 4);
    //vars.tcp_opt_len = 4;

    // copy the tcp option header to the insertion packet
    char *tcp_opt = (char*)orig_packet->tcphdr + 20;
    unsigned char tcp_opt_len = orig_packet->tcphdr->th_off * 4 - 20;
    memcpy(vars.tcp_opt, tcp_opt, tcp_opt_len);
    vars.tcp_opt_len = tcp_opt_len;

    send_insertion_packet(&vars, flags);
}

void send_fake_FIN(struct mypacket *orig_packet, unsigned int flags)
{   
    char sip[16], dip[16];
    unsigned short sport, dport;
    unsigned int seq_num, ack_num;
    struct send_tcp_vars vars = {};

    struct in_addr s_in_addr = {orig_packet->iphdr->saddr};
    struct in_addr d_in_addr = {orig_packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(orig_packet->tcphdr->th_sport);
    dport = ntohs(orig_packet->tcphdr->th_dport);
    seq_num = ntohl(orig_packet->tcphdr->th_seq);
    ack_num = ntohl(orig_packet->tcphdr->th_ack);

    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, sip, 16);
    strncpy(vars.dst_ip, dip, 16);
    vars.src_port = sport;
    vars.dst_port = dport;
    vars.flags = TCP_FIN;
    vars.seq_num = seq_num;
    vars.ack_num = ack_num;

    // mss (aliyun discards SYN without mss option header)
    //u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    //memcpy(vars.tcp_opt, bytes, 4);
    //vars.tcp_opt_len = 4;

    // copy the tcp option header to the insertion packet
    char *tcp_opt = (char*)orig_packet->tcphdr + 20;
    unsigned char tcp_opt_len = orig_packet->tcphdr->th_off * 4 - 20;
    memcpy(vars.tcp_opt, tcp_opt, tcp_opt_len);
    vars.tcp_opt_len = tcp_opt_len;

    send_insertion_packet(&vars, flags);
}    

void send_fake_RST(struct mypacket *orig_packet, unsigned int flags)
{
    char sip[16], dip[16];
    unsigned short sport, dport;
    unsigned int seq_num, ack_num;
    struct send_tcp_vars vars = {};

    struct in_addr s_in_addr = {orig_packet->iphdr->saddr};
    struct in_addr d_in_addr = {orig_packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(orig_packet->tcphdr->th_sport);
    dport = ntohs(orig_packet->tcphdr->th_dport);
    seq_num = ntohl(orig_packet->tcphdr->th_seq);
    ack_num = ntohl(orig_packet->tcphdr->th_ack);

    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, sip, 16);
    strncpy(vars.dst_ip, dip, 16);
    vars.src_port = sport;
    vars.dst_port = dport;
    vars.flags = TCP_RST | TCP_ACK;
    vars.seq_num = seq_num;
    vars.ack_num = 0;

    // mss (aliyun discards SYN without mss option header)
    //u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    //memcpy(vars.tcp_opt, bytes, 4);
    //vars.tcp_opt_len = 4;

    // copy the tcp option header to the insertion packet
    char *tcp_opt = (char*)orig_packet->tcphdr + 20;
    unsigned char tcp_opt_len = orig_packet->tcphdr->th_off * 4 - 20;
    memcpy(vars.tcp_opt, tcp_opt, tcp_opt_len);
    vars.tcp_opt_len = tcp_opt_len;

    send_insertion_packet(&vars, flags);
}

void send_fake_data(struct mypacket *orig_packet, unsigned int flags)
{
    char sip[16], dip[16];
    unsigned short sport, dport;
    unsigned int seq_num, ack_num;
    struct send_tcp_vars vars = {};

    struct in_addr s_in_addr = {orig_packet->iphdr->saddr};
    struct in_addr d_in_addr = {orig_packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(orig_packet->tcphdr->th_sport);
    dport = ntohs(orig_packet->tcphdr->th_dport);
    seq_num = ntohl(orig_packet->tcphdr->th_seq);
    ack_num = ntohl(orig_packet->tcphdr->th_ack);

    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, sip, 16);
    strncpy(vars.dst_ip, dip, 16);
    vars.src_port = sport;
    vars.dst_port = dport;
    vars.flags = TCP_ACK;
    vars.seq_num = seq_num;
    vars.ack_num = ack_num;

    // mss (aliyun discards SYN without mss option header)
    //u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    //memcpy(vars.tcp_opt, bytes, 4);
    //vars.tcp_opt_len = 4;

    // copy the tcp option header to the insertion packet
    char *tcp_opt = (char*)orig_packet->tcphdr + 20;
    unsigned char tcp_opt_len = orig_packet->tcphdr->th_off * 4 - 20;
    memcpy(vars.tcp_opt, tcp_opt, tcp_opt_len);
    vars.tcp_opt_len = tcp_opt_len;

    // garbage data
    vars.payload_len = orig_packet->payload_len;
    int i;
    for (i = 0; i < vars.payload_len; i++) {
        vars.payload[i] = '.';
    }

    send_insertion_packet(&vars, flags);
}

void send_fake_SYN_ACK(struct mypacket *orig_packet, unsigned int flags) 
{
    char sip[16], dip[16];
    unsigned short sport, dport;
    unsigned int seq_num, ack_num;
    struct send_tcp_vars vars = {};

    struct in_addr s_in_addr = {orig_packet->iphdr->saddr};
    struct in_addr d_in_addr = {orig_packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(orig_packet->tcphdr->th_sport);
    dport = ntohs(orig_packet->tcphdr->th_dport);
    seq_num = ntohl(orig_packet->tcphdr->th_seq);
    ack_num = ntohl(orig_packet->tcphdr->th_ack);

    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, sip, 16);
    strncpy(vars.dst_ip, dip, 16);
    vars.src_port = sport;
    vars.dst_port = dport;
    vars.flags = TCP_SYN | TCP_ACK;
    vars.seq_num = rand();
    vars.ack_num = rand();

    // mss (aliyun discards SYN without mss option header)
    //u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    //memcpy(vars.tcp_opt, bytes, 4);
    //vars.tcp_opt_len = 4;

    // copy the tcp option header to the insertion packet
    char *tcp_opt = (char*)orig_packet->tcphdr + 20;
    unsigned char tcp_opt_len = orig_packet->tcphdr->th_off * 4 - 20;
    memcpy(vars.tcp_opt, tcp_opt, tcp_opt_len);
    vars.tcp_opt_len = tcp_opt_len;

    send_insertion_packet(&vars, flags);
}

void send_desync_data(struct mypacket *orig_packet, unsigned int flags)
{
    char sip[16], dip[16];
    unsigned short sport, dport;
    unsigned int seq_num, ack_num;
    struct send_tcp_vars vars = {};

    struct in_addr s_in_addr = {orig_packet->iphdr->saddr};
    struct in_addr d_in_addr = {orig_packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(orig_packet->tcphdr->th_sport);
    dport = ntohs(orig_packet->tcphdr->th_dport);
    seq_num = ntohl(orig_packet->tcphdr->th_seq);
    ack_num = ntohl(orig_packet->tcphdr->th_ack);

    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, sip, 16);
    strncpy(vars.dst_ip, dip, 16);
    vars.src_port = sport;
    vars.dst_port = dport;
    vars.flags = TCP_ACK;
    vars.seq_num = seq_num + 1000;
    vars.ack_num = ack_num;

    // mss (aliyun discards SYN without mss option header)
    //u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
    //memcpy(vars.tcp_opt, bytes, 4);
    //vars.tcp_opt_len = 4;

    // copy the tcp option header to the insertion packet
    char *tcp_opt = (char*)orig_packet->tcphdr + 20;
    unsigned char tcp_opt_len = orig_packet->tcphdr->th_off * 4 - 20;
    memcpy(vars.tcp_opt, tcp_opt, tcp_opt_len);
    vars.tcp_opt_len = tcp_opt_len;

    // one-byte payload
    vars.payload_len = 1;
    vars.payload[0] = 'A';
    vars.payload[1] = 0;

    send_insertion_packet(&vars, flags);
}


