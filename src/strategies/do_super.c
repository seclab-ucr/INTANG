/*
 * Strategy implementation
 * .setup function:     Set up triggers, which listen to specific 
 *                      incoming or outgoing packets, and bind 
 *                      triggers to these events. 
 * .teardown function:  Unbind triggers.
 *
 */

#include "do_super.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "globals.h"
#include "discrepancy.h"
#include "logging.h"
#include "helper.h"
#include "ttl_probing.h"



static void send_junk_data_super(
        const char *src_ip, unsigned short src_port, 
        const char *dst_ip, unsigned short dst_port,
        unsigned int seq_num, unsigned int ack_num,
        int len, unsigned char ttl)
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
    vars.ack_num = htonl(ntohl(ack_num) + 1000);
    vars.ack_num = ack_num;
    //vars.wrong_tcp_checksum = 1;
    vars.ttl = ttl;
    
    u_char bytes[20] = {0x13,0x12,0xf9,0x89,0x5c,0xdd,0xa6,0x15,0x12,0x83,0x3e,0x93,0x11,0x22,0x33,0x44,0x55,0x66,0x01,0x01};
    memcpy(vars.tcp_opt, bytes, 20);
    vars.tcp_opt_len = 20;

    vars.payload_len = len;
    int i;
    for (i = 0; i < len; i++) {
        vars.payload[i] = '.';
    }

    //dump_send_tcp_vars(&vars);

    send_tcp(&vars);
}


int x10_setup()
{
    char cmd[256];
    sprintf(cmd, "iptables -A INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x10_teardown()
{
    char cmd[256];
    sprintf(cmd, "iptables -D INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x10_process_syn(struct mypacket *packet)
{
    return 0;
}

int x10_process_synack(struct mypacket *packet)
{
    return 0;
}

int x10_process_request(struct mypacket *packet)
{
    unsigned int dflags;
    dflags = INS_DISC_BAD_ACK_NUM | INS_DISC_MD5 | INS_DISC_OLD_TIMESTAMP;
    if (1) {
        dflags |= INS_DISC_SMALL_TTL;
    }
    if (1) {
        dflags |= INS_DISC_BAD_TCP_CHECKSUM;
    }
    send_fake_data(packet, dflags);
    usleep(20000);
    send_fake_data(packet, dflags);
    usleep(20000);
    send_fake_data(packet, dflags);
    //send_RST_super(sip, sport, dip, dport, packet->tcphdr->th_seq);
    //send_RST_super(sip, sport, dip, dport, packet->tcphdr->th_seq);
    //send_RST_super(sip, sport, dip, dport, packet->tcphdr->th_seq);

    return 1;
}




