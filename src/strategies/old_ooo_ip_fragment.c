/*
 * Strategy implementation
 * .setup function:     Set up triggers, which listen to specific 
 *                      incoming or outgoing packets, and bind 
 *                      triggers to these events. 
 * .teardown function:  Unbind triggers.
 *
 */

#include "old_ooo_ip_fragment.h"

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
//#include "ttl_probing.h"


int x28_setup()
{
    char cmd[256];
    sprintf(cmd, "iptables -A INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x28_teardown()
{
    char cmd[256];
    sprintf(cmd, "iptables -D INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x28_process_syn(struct mypacket *packet)
{
    return 0;
}

int x28_process_synack(struct mypacket *packet)
{
    return 0;
}

int x28_process_request(struct mypacket *packet)
{
    char sip[16], dip[16];
    unsigned short sport, dport;

    struct in_addr s_in_addr = {packet->iphdr->saddr};
    struct in_addr d_in_addr = {packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(packet->tcphdr->th_sport);
    dport = ntohs(packet->tcphdr->th_dport);

    int i;
    char junk_data[65535];
    for (i = 0; i < packet->payload_len; i++) {
        junk_data[i] = 'A';
    }

    // IP fragmentation: Cut the entire HTTP request into two fragments.
    // 'GET ' + remaining
    // According to Khattak etal., GFW prefers the original IP fragment 
    // for all cases except where Fsub is left-long and right-long to Forig
    // So we first send some junk data to cover 'remaining', then send the
    // actual 'remaining', and then send 'GET'.
    unsigned short ipid, fragoff;
    ipid = (unsigned short)rand();
    //ipid = 1;
    fragoff = 24; // must be multiple of 8

    int tcphdr_len = 20;

    //static int sent;
    //if (sent != 123456) {
    //log_info("send junk");
    send_ip_fragment(sip, sport, dip, dport, packet->tcphdr->th_seq, packet->tcphdr->th_ack, ipid, fragoff, packet->payload_len+tcphdr_len-fragoff, 0, junk_data, packet->payload_len);
    //log_info("send remaining");
    send_ip_fragment(sip, sport, dip, dport, packet->tcphdr->th_seq, packet->tcphdr->th_ack, ipid, fragoff, packet->payload_len+tcphdr_len-fragoff, 0, packet->payload, packet->payload_len);
    //log_info("send get");
    send_ip_fragment(sip, sport, dip, dport, packet->tcphdr->th_seq, packet->tcphdr->th_ack, ipid, 0, fragoff, 1, packet->payload, packet->payload_len);
    //sent = 123456;
    //}
    //else {
    //    log_info("discard");
    //}

    return -1;
}


