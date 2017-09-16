
/*
 * Local DNS proxy
 * Forward the local DNS request to a public resolver using TCP
 * Can be replaced with pdnsd.
 */

#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "globals.h"
#include "logging.h"
#include "socket.h"
#include "protocol.h"
#include "helper.h"

// DNS server close the connection when idle 30 seconds
// we have the chance to send two keep-alive packets
#define KEEP_ALIVE_INTERVAL 7

// Maximum dns blacklist size in bytes
#define MAX_BLACKLIST_SIZE 102400
// Maximum domain name length
#define MAX_DOMAIN_LEN 100

#define MAX_RETRY_CNT 3

// Long-lived DNS socket over TCP
static int dns_tcp_sock;


static char **dns_blacklist;
static int dns_blacklist_len;


void load_dns_blacklist()
{
    int i;
    char **ptr;

    FILE *fp = fopen(DNS_BLACKLIST, "r");
    if (fp == NULL) {
        log_error("Cannot open dns blacklist file '%s'", DNS_BLACKLIST);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    if (fsize > MAX_BLACKLIST_SIZE) {
        log_error("Blacklist is too large!!!");
        return;
    }
    fseek(fp, 0, SEEK_SET);
    char *content = malloc(fsize + 1);
    fread(content, fsize, 1, fp);
    fclose(fp);

    content[fsize] = 0;

    if (dns_blacklist) {
        for (ptr = dns_blacklist; *ptr != NULL; ptr++) {
            free(*ptr);
            *ptr = NULL;
        }
    }
    dns_blacklist_len = 0;
    for (i = 0; i < fsize; i++) {
        if (content[i] == '\n') {
            dns_blacklist_len++; // just count newline for simplicity
        }
    }
    dns_blacklist_len++;    // always allocate 1 more for the case there's no trailing '\n' in last line

    dns_blacklist = (char **)malloc(sizeof(char*) * dns_blacklist_len);
    for (i = 0; i < dns_blacklist_len; i++) {
        dns_blacklist[i] = (char*)malloc(MAX_DOMAIN_LEN);
        dns_blacklist[i][0] = 0;
    }

    int idx0 = 0, idx1 = 0;
    for (i = 0; i < fsize; i++) {
        if (content[i] == '\n') {
            dns_blacklist[idx0][idx1] = 0;
            idx0++;
            idx1 = 0;
            continue;
        }
        dns_blacklist[idx0][idx1++] = content[i];
    }
    dns_blacklist[idx0][idx1] = 0;

    free(content);
}

// for debug
void print_dns_blacklist()
{
    int i;
    for (i = 0; i < dns_blacklist_len; i++) {
        if (dns_blacklist[i][0] != 0) {
            printf("%s\n", dns_blacklist[i]);
        }
    }
}


// Check if domain is in the blacklist
// Since the DNS poisoner may also posion subdomains, we consider that the domain 
// is in the blacklist as long as it is the subdomain of one of those in the list.
int is_poisoned_domain(const char *domain)
{
    int i, j;

    if (!dns_blacklist) {
        log_error("DNS blacklist is not initialized.");
        return -1;
    }

    int len = strlen(domain);
    for (i = 0; i < dns_blacklist_len; i++) {
        int len1 = strlen(dns_blacklist[i]);
        // the domain checked must be either the same one in the list or 
        // the subdomain of that, and its length must be larger or equal to it.
        if (len < len1)
            continue;
        if (len > len1 && domain[len-1-len1] != '.')
            continue;
        // compare from the right most
        int flag = 1;
        for (j = 0; j < len1; j++) {
            if (dns_blacklist[i][len1-1-j] != domain[len-1-j]) {
                flag = 0;
                break;
            }
        }
        if (flag) {
            return 1;
        }
    }

    return 0;
}

/*
int dns_strat_process(struct mypacket *packet)
{
    struct myiphdr *iphdr = packet->iphdr;
    struct mytcphdr *tcphdr = packet->tcphdr;
    
    // parse ip and port
    char sip[16], dip[16];
    unsigned short sport, dport;
    unsigned int seq, ack;
    struct in_addr s_in_addr = {iphdr->saddr};
    struct in_addr d_in_addr = {iphdr->daddr};

    strncpy(sip, inet_ntoa(s_in_addr), 16);
    strncpy(dip, inet_ntoa(d_in_addr), 16);
    sport = ntohs(tcphdr->th_sport);
    dport = ntohs(tcphdr->th_dport);
    seq = tcphdr->th_seq;
    ack = tcphdr->th_ack;

    log_debug("Trying to terminate the TCB of DNS connection.");

    // choose the appropriate ttl
    int ttl = choose_appropriate_ttl(iphdr->ttl);
    send_RST_with_ttl(dip, dport, sip, sport, ack, ttl);

    return 0;
}
*/


u_int32_t select_public_resolver(u_int32_t exclude_ip)
{
    int idx, total;
    u_int32_t ret;
    const char PUBLIC_DNS_RESOLVERS[][16] = {
        "203.112.2.4",
        "216.146.35.35",
        "216.146.36.36",
        "208.67.220.220",
        "208.67.222.222",
        "202.45.84.58"
    };
    total = 4;

    do {
        idx = rand() % total;
        ret = str2ip(PUBLIC_DNS_RESOLVERS[idx]);
    } 
    while (ret == exclude_ip);
    log_debug("Using public DNS resolver #%d: %s", idx+1, PUBLIC_DNS_RESOLVERS[idx]);
    
    return ret;
}

int init_dns_tcp_conn()
{
    int optval;
    socklen_t optlen;

    if (dns_tcp_sock)
        close(dns_tcp_sock);

    if ((dns_tcp_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_error("init_dns_tcp_conn: Cannot create socket");
        return -1;
    }

    /*
    // Set the keep alive socket option
    optval = 1;
    optlen = sizeof(optval);
    if(setsockopt(dns_tcp_sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        log_error("init_dns_tcp_conn: setsockopt() failed");
        return -1;
    }
    optval = 15;
    optlen = sizeof(optval);
    if(setsockopt(dns_tcp_sock, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        log_error("init_dns_tcp_conn: setsockopt() failed");
        return -1;
    }
    optval = 5;
    optlen = sizeof(optval);
    if(setsockopt(dns_tcp_sock, SOL_TCP, TCP_KEEPINTVL, &optval, optlen) < 0) {
        log_error("init_dns_tcp_conn: setsockopt() failed");
        return -1;
    }
    */

    struct sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(53);
    dst_addr.sin_addr.s_addr = select_public_resolver(0);
    
    int retry_cnt = 0;
    log_info("Connecting to TCP DNS server.");
    while (connect(dns_tcp_sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0) {
        log_error("Cannot connect to TCP DNS server. Retrying...");
        if (retry_cnt++ > MAX_RETRY_CNT) {
            log_error("Reached maximum retry count.");
            dst_addr.sin_addr.s_addr = select_public_resolver(dst_addr.sin_addr.s_addr);
        }
        sleep(1);
    }
    log_info("Connected to TCP DNS server.");
    
    //signal(SIGPIPE, sig_handler);

    return 0;
}

int send_dns_req_over_tcp(const char *dns_req, size_t len)
{
    int ret;
    char sndbuf[MAX_PACKET_SIZE];

    if (len > MAX_PACKET_SIZE - 2) {
        log_error("DNS payload too long! %u\n", len);
    }

    // insert len at the beginning
    sndbuf[0] = len >> 8 & 0xff;
    sndbuf[1] = len & 0xff;

    memcpy(sndbuf+2, dns_req, len);

    // use MSG_NOSIGNAL, otherwise it will crash when connection is closed from remote side
    while ((ret = send(dns_tcp_sock, sndbuf, len+2, MSG_NOSIGNAL)) <= 0) {
        log_error("Send DNS request over TCP failed.");
        if (ret < 0) {
            log_error("error no: %d", errno);
        } else {
            log_error("sent 0 bytes. Connection may be closed.");
        }
        log_error("Now will rebuild the TCP connection.");
        init_dns_tcp_conn();
    }
    log_debug("DNS over TCP sent. %d", ret);

    return 0;
}

void send_keep_alive_packet()
{
    int ret;
    char dns_req[64] = {
        0x00, 0x2c, 0x1a, 0x5f, 0x01, 0x00, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 
        0x77, 0x77, 0x12, 0x61, 0x69, 0x6f, 0x6a, 0x65, 
        0x77, 0x65, 0x77, 0x72, 0x72, 0x65, 0x77, 0x71, 
        0x64, 0x64, 0x73, 0x61, 0x67, 0x03, 0x63, 0x6f, 
        0x6d, 0x00, 0x00, 0x01, 0x00, 0x01 
    };  // some non-exist domain
    int dns_req_len = 46;
    ret = send(dns_tcp_sock, dns_req, dns_req_len, MSG_NOSIGNAL);
    if (ret == -1) {
        log_error("Send keep alive packet failed. errno: %d", errno);
        init_dns_tcp_conn();
    }
    else
        log_debug("Keep alive packet sent.");
}

int clean()
{
    close(dns_tcp_sock);
    return 0;
}


int dns_proxy_loop()
{
    int sockfd;
    struct sockaddr_in local_addr, remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    int retval;
    int recvlen;
    char buf[MAX_PACKET_SIZE];
    fd_set rfds;
    struct timeval tv;
    time_t now, last_ack_time;

    load_dns_blacklist();
    //print_blacklist();

    // create the listening socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        log_error("dns_main_loop: Cannot create DNS socket.");
        return -1;
    }

    memset((char*)&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(LOCAL_DNS_PORT);
    local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        log_error("dns_main_loop: Bind failed.");
        return -1;
    }

    // init connection to public resolver using TCP
    if (init_dns_tcp_conn() < 0) {
        log_error("dns_main_loop: Init DNS TCP conn failed.");
        return -1;
    }

    last_ack_time = time(NULL);

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        retval = select(sockfd+1, &rfds, NULL, NULL, &tv);

        if (retval == -1)
            log_error("select() failed. errno: %d", errno);
        else if (retval) {
            recvlen = recvfrom(sockfd, buf, MAX_PACKET_SIZE, 0, (struct sockaddr*)&remote_addr, &addrlen);
            log_debugv("received %d bytes", recvlen);
            if (recvlen > 0) {
                send_dns_req_over_tcp(buf, recvlen);
            }
        }

        // need to send a normal DNS request in order to keep connection alive, does it worth? 
        now = time(NULL);
        if (now - last_ack_time > KEEP_ALIVE_INTERVAL) {
            send_keep_alive_packet();
            last_ack_time = now;
        }
    }
    return 0;
}

