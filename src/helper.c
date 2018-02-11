
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "globals.h"

#include "helper.h"
#include "socket.h"
#include "protocol.h"
#include "logging.h"


int read_version()
{
    char buf[10];
    FILE *fp = fopen(APP_DIR"version", "r");
    if (fp == NULL)
        return 0;
    fread(buf, 1, 10, fp);
    fclose(fp);
    return strtol(buf, NULL, 10);
}

void write_version(int version)
{
    FILE *fp = fopen(APP_DIR"version", "w");
    fprintf(fp, "%d", version);
    fclose(fp);
}

void hex_dump(const unsigned char *packet, size_t size)
{
    unsigned char *byte = (unsigned char*)packet;
    int count = 0;

    printf("\t\t");
    for (; byte < ((unsigned char*)packet)+size; byte++) {
        count++;
        printf("%02x ", *byte);
        if (count % 16 == 0) printf("\n\t\t");
    }
    printf("\n\n");
}

void human_dump(const unsigned char *packet, size_t size)
{
    unsigned char *byte = (unsigned char*)packet;
    int count = 0;

    printf("\t\t");
    for (; byte < ((unsigned char*)packet)+size; byte++) {
        count ++; 
        if (isprint(*byte))
            printf("%c", *byte);
        else
            printf(".");
        if (count % 32 == 0) printf("\n\t\t");
    }   
    printf("\n\n");
}

void dump_send_tcp_vars(struct send_tcp_vars *vars)
{
    log_debug("----------------------------");
    log_debug("Source Address: %s:%d", vars->src_ip, vars->src_port);
    log_debug("Dest Address: %s:%d", vars->dst_ip, vars->dst_port);
    char flag_str[20] = "";
    char flag_strs[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
    int i;
    for (i=1; i<6; i++) {
        if ((vars->flags >> i) & 1) {
            strncat(flag_str, flag_strs[i], 3);
            strncat(flag_str, ",", 1);
        }
    } 
    log_debug("TCP flags: %s", flag_str);
    log_debug("TTL: %d", vars->ttl);
    log_debug("IPID: %d", vars->ipid);
    log_debug("Payload Len: %d", vars->payload_len);
    log_debug("Payload: %s", vars->payload);
    log_debug("----------------------------");
}

char* tcp_flags(u_int8_t flags) 
{
    static char flag_str[20];
    const static char flag_strs[6][10] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG"};
    int i;

    flag_str[0] = 0;
    for (i=0; i<6; i++) {
        if ((flags >> i) & 1) {
            strncat(flag_str, flag_strs[i], 3);
            strncat(flag_str, ",", 1);
        }
    } 
    //log_debug("TCP flags: %s", flag_str);
    return flag_str;
}

void print_fourtuple(struct fourtuple *fourtp)
{
    char sip[16], dip[16];
    log_debug("4-tuple: %s:%d -> %s:%d", ip2str(fourtp->saddr, sip), htons(fourtp->sport), ip2str(fourtp->daddr, dip), htons(fourtp->dport));
}

char* ip2str(u_int32_t ip, char *str)
{
    struct in_addr ia = {ip};
    str[0] = 0;
    strncat(str, inet_ntoa(ia), 16);
    return str;
}

u_int32_t str2ip(const char *str)
{
    struct sockaddr_in addr;
    inet_aton(str, &addr.sin_addr);
    return addr.sin_addr.s_addr;
}

void show_packet(struct mypacket *packet)
{
    char sip[16], dip[16];
    printf("-------------------------------------\n");
    printf("IP Header:\n");
    printf("+ IHL: %d\n", packet->iphdr->ihl);
    printf("+ Version: %d\n", packet->iphdr->version);
    printf("+ TOS: %d\n", packet->iphdr->tos);
    printf("+ Total length: %d\n", ntohs(packet->iphdr->tot_len));
    printf("+ ID: %d\n", ntohs(packet->iphdr->id));
    printf("+ IP flags: %d\n", (packet->iphdr->frag_off & 0xff) >> 5);
    printf("+ Fragment Offset: %d\n", ((packet->iphdr->frag_off & 0x1f) << 8) + ((packet->iphdr->frag_off & 0xff00) >> 8));
    printf("+ TTL: %d\n", packet->iphdr->ttl);
    printf("+ Protocol: %d\n", packet->iphdr->protocol);
    printf("+ IP checksum: %04x\n", ntohs(packet->iphdr->check));
    printf("+ Source: %s\n", ip2str(packet->iphdr->saddr, sip));
    printf("+ Destination: %s\n", ip2str(packet->iphdr->daddr, dip));
    printf("-------------------------------------\n");
    switch (packet->iphdr->protocol) {
        case 6: // TCP
            printf("\tTCP Header:\n");
            printf("\t+ SPort: %d\n", ntohs(packet->tcphdr->th_sport));
            printf("\t+ DPort: %d\n", ntohs(packet->tcphdr->th_dport));
            printf("\t+ Seq num: %08x\n", ntohl(packet->tcphdr->th_seq));
            printf("\t+ Ack num: %08x\n", ntohl(packet->tcphdr->th_sport));
            printf("\t+ Data offset: %d\n", packet->tcphdr->th_off);
            printf("\t+ TCP flags: %s\n", tcp_flags(packet->tcphdr->th_flags));
            printf("\t+ Window: %d\n", ntohs(packet->tcphdr->th_win));
            printf("\t+ TCP checksum: %04x\n", ntohs(packet->tcphdr->th_sum));
            printf("\t+ Urgent pointer: %04x\n", ntohs(packet->tcphdr->th_urp));
            if (packet->tcphdr->th_off != 5) {
                // optional header
                printf("\t+ Optionial:\n");
                hex_dump(((unsigned char*)packet->tcphdr)+packet->tcphdr->th_off*4, packet->tcphdr->th_off*4-20);
            }
            printf("\tTCP Payload:\n");
            hex_dump(packet->payload, packet->payload_len);
            break;
        case 17: // UDP
            printf("\tUDP Header:\n");
            printf("\t+ SPort: %d\n", ntohs(packet->udphdr->uh_sport));
            printf("\t+ DPort: %d\n", ntohs(packet->udphdr->uh_dport));
            printf("\t+ UDP length: %d\n", ntohs(packet->udphdr->uh_ulen));
            printf("\t+ UDP checksum: %04x\n", ntohs(packet->udphdr->uh_sum));
            printf("\tUDP Payload:\n");
            hex_dump(packet->payload, packet->payload_len);
            break;
        default:
            printf("Unkonwn Protocol: %d\n", packet->iphdr->protocol);
            // payload
            hex_dump(packet->data+packet->iphdr->ihl*4, packet->len-packet->iphdr->ihl*4);
    } 
    printf("-------------------------------------\n");
}


int is_ip_in_whitelist(u_int32_t ip)
{
    // localhost 
    if ((ip & 0xff) == 127 && (ip >> 8 & 0xff) == 0)
        return 1;

    // for test 
    //if (ip == str2ip(PACKET_FORWARDER))
    //    return 1;

    return 0;
}

unsigned int make_hash(struct fourtuple *f)
{
    unsigned int hash = 0;
    hash = (f->saddr * 59);
    hash ^= f->daddr;
    hash ^= (f->sport << 16 | f->dport);
    return hash;
}

unsigned int make_hash2(unsigned int saddr, unsigned short sport, 
        unsigned int daddr, unsigned short dport) 
{
    unsigned int hash = 0;
    hash = (saddr * 59);
    hash ^= daddr;
    hash ^= (sport << 16 | dport);
    return hash;
}


unsigned int make_hash3(u_int16_t txn_id, const char *qname)
{
    unsigned int hash = 1;
    while (*qname != 0) {
        hash = (hash * 59) + *qname;
        qname++;
    }
    hash ^= txn_id;
    return hash;
}


// an naive algorithm for checksum calculation 
unsigned int calc_checksum(const unsigned char *payload, unsigned short payload_len)
{
    int i;
    unsigned int checksum = 0, remain = 0;

    // round down to multiple of 4 
    unsigned short rd_payload_len = payload_len / 4 * 4;
    for (i = 0; i < rd_payload_len; i += 4) {
        checksum ^= *((unsigned int*)(payload+i));
    }   
    for (i = rd_payload_len; i < payload_len; i++) {
        remain = remain + (payload[i] << (8 * (i - rd_payload_len)));
    }   
    checksum ^= remain;

    return checksum;
}


int choose_appropriate_ttl(int ttl)
{
    if (ttl < 64) {
        return 64 - ttl - 1; // Linux
    } 
    else if (ttl < 128) {
        return 128 - ttl - 1; // Windows
    } 
    else {
        return 254 - ttl - 1; // Others(Solaris/AIX)
    }
}

int is_blocked_ip(const char *ip)
{
    return 1;
}

int startswith(const char *a, const char *b) {
    return (strncmp(a, b, strlen(b)) == 0);
}

// not 100% accurate, may have false-positive
int is_https_client_hello(const char *payload) {
    if (payload[0] == 0x16) // Type == Handshake
    {
        if (payload[1] == 0x03) // Version
        {
            if (payload[5] == 0x01) // Type == ClientHello
            {
                if (payload[9] == 0x03) // First byte of Version
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}

// not 100% accurate, may have false-positive
int is_https_server_hello(const char *payload) {
    if (payload[0] == 0x16) // Type == Handshake
    {
        if (payload[1] == 0x03) // First byte of Version
        {
            if (payload[5] == 0x02) // Type == ServerHello
            {
                if (payload[9] == 0x03) // First byte of Version
                {
                    return 1;
                }
            }
        }
    }
    return 0;
}

