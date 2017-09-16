/*
 * Strategy implementation
 * .setup function:     Set up triggers, which listen to specific 
 *                      incoming or outgoing packets, and bind 
 *                      triggers to these events. 
 * .teardown function:  Unbind triggers.
 *
 */

#include "mixed_ms_rd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "globals.h"
#include "socket.h"
#include "protocol.h"
#include "logging.h"
#include "helper.h"


static void send_fake_SYN(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
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

static void send_RST_super(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num)//, unsigned char ttl)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    //log_debug("size of vars: %ld", sizeof vars);
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_RST | TCP_ACK;
    vars.seq_num = seq_num;
    vars.ack_num = 0;
    //vars.wrong_tcp_checksum = 1;
    //vars.ttl = ttl;

    u_char bytes[20] = {0x13,0x12,0xf9,0x89,0x5c,0xdd,0xa6,0x15,0x12,0x83,0x3e,0x93,0x11,0x22,0x33,0x44,0x55,0x66,0x01,0x01};
    memcpy(vars.tcp_opt, bytes, 20);
    vars.tcp_opt_len = 20;

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}

static void send_fake_payload(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.src_port = src_port;
    vars.dst_port = dst_port;
    vars.flags = TCP_ACK;
    vars.seq_num = htonl(ntohl(seq_num) + (rand() % 10000000 + 1000000));
    vars.ack_num = ack_num;
    //vars.wrong_tcp_checksum = 1;

    u_char bytes[20] = {0x13,0x12,0xf9,0x89,0x5c,0xdd,0xa6,0x15,0x12,0x83,0x3e,0x93,0x11,0x22,0x33,0x44,0x55,0x66,0x01,0x01};
    memcpy(vars.tcp_opt, bytes, 20);
    vars.tcp_opt_len = 20;

    vars.payload_len = 1;
    vars.payload[0] = 'A';

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}


int x15_setup()
{
    return 0;
}

int x15_teardown()
{
    return 0;
}

int x15_process_syn(struct mypacket *packet)
{
    char sip[16], dip[16];
    unsigned short sport, dport;

    struct in_addr s_in_addr = {packet->iphdr->saddr};
    struct in_addr d_in_addr = {packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(packet->tcphdr->th_sport);
    dport = ntohs(packet->tcphdr->th_dport);

    send_fake_SYN(sip, sport, dip, dport, packet->tcphdr->th_seq); 
    send_fake_SYN(sip, sport, dip, dport, packet->tcphdr->th_seq); 
    send_fake_SYN(sip, sport, dip, dport, packet->tcphdr->th_seq); 

    return 0;
}

int x15_process_synack(struct mypacket *packet)
{
    char sip[16], dip[16];
    unsigned short sport, dport;

    struct in_addr s_in_addr = {packet->iphdr->saddr};
    struct in_addr d_in_addr = {packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(packet->tcphdr->th_sport);
    dport = ntohs(packet->tcphdr->th_dport);

    // choose the appropriate ttl
    //int ttl = choose_appropriate_ttl(packet->iphdr->ttl);
    send_ACK(dip, dport, sip, sport, packet->tcphdr->th_ack, htonl(ntohl(packet->tcphdr->th_seq)+1));
    send_ACK(dip, dport, sip, sport, packet->tcphdr->th_ack, htonl(ntohl(packet->tcphdr->th_seq)+1));
    send_ACK(dip, dport, sip, sport, packet->tcphdr->th_ack, htonl(ntohl(packet->tcphdr->th_seq)+1));
    send_RST_super(dip, dport, sip, sport, packet->tcphdr->th_ack);
    send_RST_super(dip, dport, sip, sport, packet->tcphdr->th_ack);
    send_RST_super(dip, dport, sip, sport, packet->tcphdr->th_ack);
    send_fake_payload(dip, dport, sip, sport, packet->tcphdr->th_ack, htonl(ntohl(packet->tcphdr->th_seq)+1)); 
    send_fake_payload(dip, dport, sip, sport, packet->tcphdr->th_ack, htonl(ntohl(packet->tcphdr->th_seq)+1)); 
    send_fake_payload(dip, dport, sip, sport, packet->tcphdr->th_ack, htonl(ntohl(packet->tcphdr->th_seq)+1)); 

    return 0;
}



