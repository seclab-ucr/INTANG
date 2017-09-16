
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "globals.h"
#include "logging.h"
#include "protocol.h"
#include "socket.h"
#include "helper.h"


// socket between main and DNS thread
static int local_dns_sock;
static struct sockaddr_in local_dns_addr;


// API for main thread

// Initialize socket with local DNS forwarder
int init_dns_cli()
{
    if ((local_dns_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        log_error("dnscli.c:init_dns_sock():Cannot create dns socket.");
        return -1;
    }

    struct sockaddr_in myaddr;
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = 0;    // use random port
    myaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(local_dns_sock, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0) {
        log_error("dnscli.c:init_dns_sock(): Bind failed.");
        return -1;
    }

    local_dns_addr.sin_family = AF_INET;
    local_dns_addr.sin_port = htons(LOCAL_DNS_PORT);
    local_dns_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    return 0;
}


// Send the DNS req to local DNS forwarder using UDP
int send_dns_req(const unsigned char *dns_req, size_t len)
{
    int ret;
    assert(local_dns_sock);
    ret = sendto(local_dns_sock, dns_req, len, 0, (struct sockaddr*)&local_dns_addr, sizeof(local_dns_addr));
    if (ret == -1) {
        log_error("dnscli.c:send_dns_req():sendto failed. errno: %d", errno);
        return -1;
    }
    return 0;
}

// When DNS response over TCP received, transfer it into a UDP resopnse sent from orginal DNS resolver
int fabricate_dns_udp_response(struct fourtuple *fourtp, const char *dns_req, unsigned short len)
{
    struct send_udp_vars vars;
    ip2str(fourtp->saddr, vars.src_ip);
    ip2str(fourtp->daddr, vars.dst_ip);
    vars.src_port = ntohs(fourtp->sport);
    vars.dst_port = ntohs(fourtp->dport);
    memcpy(vars.payload, dns_req, len);
    vars.payload_len = len;

    send_udp(&vars);
    log_debug("Sent an fabricated UDP DNS response from %s:%d to %s:%d", vars.src_ip, vars.src_port, vars.dst_ip, vars.dst_port);

    return 0;
}


