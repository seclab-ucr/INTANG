
#include "ttl_probing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "globals.h"
#include "socket.h"
#include "protocol.h"
#include "logging.h"
#include "helper.h"
#include "memcache.h"



void send_probing_SYNs(const char *src_ip, const char *dst_ip, unsigned short dst_port)
{
    char pkt[MAX_PACKET_SIZE];

    struct send_tcp_vars vars;
    memset(&vars, 0, sizeof vars);
    strncpy(vars.src_ip, src_ip, 16);
    strncpy(vars.dst_ip, dst_ip, 16);
    vars.dst_port = dst_port;
    vars.flags = TCP_SYN;
    vars.ack_num = 0;

    int i;
    for (i = 5; i < 30; i++) {
        vars.src_port = 10000 + i;
        vars.seq_num = htonl(10000 + i - 1);
        vars.ttl = i;
        // mss
        u_char bytes[4] = {0x02, 0x04, 0x05, 0xb4};
        memcpy(vars.tcp_opt, bytes, 4);
        vars.tcp_opt_len = 4;
        //dump_send_tcp_vars(&vars);
        send_tcp(&vars);
    }

    set_ttl(str2ip(dst_ip), 99);
}


int process_synack_for_ttl_probing(struct mypacket *packet)
{
    char sip[16], dip[16];
    unsigned short sport, dport;

    struct in_addr s_in_addr = {packet->iphdr->saddr};
    struct in_addr d_in_addr = {packet->iphdr->daddr};
    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(packet->tcphdr->th_sport);
    dport = ntohs(packet->tcphdr->th_dport);

    if (dport > 10000 && dport < 10100) {
        unsigned int ack = ntohl(packet->tcphdr->th_ack);
        if (dport == ack) {
            // it's a response for our probing SYN!
            unsigned char ttl = dport - 10000;
            log_debugv("[TTL Probing] Received a response for TTL %d.", dport - 10000);
            set_ttl_if_lt(str2ip(sip), ttl);
        }
        return -1;
    }
    return 0;
}

int load_ttl_from_file(char *filename)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        // skip if file not exist
        return 0;
    }
    while ((read = getline(&line, &len, fp)) != -1) {
        // TODO: more robust checks
        if (line[0] == '#') 
            continue;
        if (read < 9) 
            continue;
        char *ip = line;
        char *tmp;
        for (tmp = line; tmp != 0; tmp++) {
            if (*tmp == ',') {
                *tmp = 0;
                tmp++;
                break;
            }
        }
        unsigned char ttl = atoi(tmp);

        if (ip && ttl > 0) 
            set_ttl(str2ip(ip), ttl);
    }
    if (line)
        free(line);
    fclose(fp);
    return 0;
}

