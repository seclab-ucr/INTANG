#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pthread.h>

// inet.h and in.h can't be included after netfilter.h, otherwise error occurs.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/netfilter.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "globals.h"
#include "protocol.h"
#include "strategy.h"
#include "logging.h"
#include "socket.h"
#include "cache.h"
#include "dns.h"
#include "feedback.h"
#include "helper.h"
#include "redis.h"
#include "dnscli.h"
#include "memcache.h"
#include "ttl_probing.h"

#ifdef TEST
#include "test.h"
#endif

#define VERSION 7

// TODO: clean the code and add/rewrite comments

// 0 - don't need to drop the redis DB when upgrading to a newer version, 1 - otherwise
int need_to_delete_redis_db = 1;


/*
 * Options
 */

// 0 - print log to stdout, 1 - output log to /var/log/intangd.log
int opt_logging_to_file = 1;

// Logging level: 0 - error, 1 - warning, 2 - info, 3 - debug, 4 - debug (verbose)
int opt_logging_level = 2;

// HTTP response injection detection.
// 0 - disable, 1 - enable
int opt_http_injection_detection = 0;

// 0 - disable, 1 - enable
int opt_inject_ack_with_one_ttl = 0;

// Inject fake SYN and/or SYN+ACK with 1 TTL after sending RST to reopen NAT on home router: 0 - no injection, 1 - just inject SYN, 2 - inject SYN and SYN+ACK
int opt_inject_syn_and_syn_ack_with_one_ttl = 1;

// 0 - disable, 1 - enable
int opt_protect_http_protocol = 1;

// 0 - disable, 1 - enable
int opt_protect_dns_protocol = 0;
int opt_dns_only_blacklisted = 1;

// 0 - disable, 1 - enable
int opt_protect_vpn_protocol = 0;
// VPN port MUST be set when VPN protection is enabled!!!
int opt_vpn_port = 0;

// 0 - disable, 1 - enable
int opt_protect_tor_protocol = 0;
// Tor port MUST be set when Tor protection is enabled!!!
int opt_tor_port = 0;


/*
 * Global consts
 */

const char REDIS_PID_FILE[] = "/var/run/redis.intangd.pid";

// delay in ms after packet injection 
#define DELAY_AFTER_PACKET_INJECTION 30000


/*
 * Global variables
 */

time_t startup_ts;

struct nfq_handle *g_nfq_h;
struct nfq_q_handle *g_nfq_qh;
int g_nfq_fd;
static int g_modified;


void initialize();
void cleanup();

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data);


int start_redis_server()
{
    int ret;
    log_info("Starting redis server.");
    ret = system("redis-server redis.conf");
    if (ret != 0) {
        log_error("Failed to start redis server.");
        return -1;
    }

    return 0;
}

int stop_redis_server()
{
    FILE *fp = fopen(REDIS_PID_FILE, "r");
    if (fp == NULL) {
        log_warn("Redis server is not running?");
        return -1;
    }

    char s[10] = "";
    fread(s, 1, 10, fp);
    pid_t redis_pid = strtol(s, NULL, 10);
    log_info("Killing redis server (pid %d).", redis_pid);
    kill(redis_pid, SIGTERM);

    return 0;
}

void signal_handler(int signum)
{
    printf("Daemon exited unexpectedly. Signal %d recved.\n", signum);
    log_debug("Signal %d recved.", signum);
    cleanup();
    log_info("Daemon exited.");
    exit(EXIT_FAILURE);
}

int register_signal_handlers()
{
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        log_error("register SIGINT handler failed.");
        return -1;
    }
    if (signal(SIGSEGV, signal_handler) == SIG_ERR) {
        log_error("register SIGSEGV handler failed.");
        return -1;
    }
    if (signal(SIGQUIT, signal_handler) == SIG_ERR) {
        log_error("register SIGQUIT` handler failed.");
        return -1;
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR) {
        log_error("register SIGTERM handler failed.");
        return -1;
    }
    if (signal(SIGFPE, signal_handler) == SIG_ERR) {
        log_error("register SIGFPE handler failed.");
        return -1;
    }
    if (signal(SIGPIPE, signal_handler) == SIG_ERR) {
        log_error("register SIGPIPE handler failed.");
        return -1;
    }

    return 0;
}

int setup_nfq()
{
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        log_error("error during nfq_open()");
        return -1;
    }

    log_debug("unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        log_error("error during nfq_unbind_pf()");
        return -1;
    }

    log_debug("binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        log_error("error during nfq_bind_pf()");
        return -1;
    }

    // set up a queue
    log_debug("binding this socket to queue %d", NF_QUEUE_NUM);
    g_nfq_qh = nfq_create_queue(g_nfq_h, NF_QUEUE_NUM, &cb, NULL);
    if (!g_nfq_qh) {
        log_error("error during nfq_create_queue()");
        return -1;
    }

    log_debug("setting copy_packet mode");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log_error("can't set packet_copy mode");
        return -1;
    }

    g_nfq_fd = nfq_fd(g_nfq_h);

    return 0;
}

int teardown_nfq()
{
    log_debug("unbinding from queue %d", NF_QUEUE_NUM);
    if (nfq_destroy_queue(g_nfq_qh) != 0) {
        log_error("error during nfq_destroy_queue()");
        return -1;
    }

#ifdef INSANE
    // normally, applications SHOULD NOT issue this command, since
    // it detaches other programs/sockets from AF_INET, too ! */
    log_debug("unbinding from AF_INET");
    nfq_unbind_pf(g_nfq_h, AF_INET);
#endif

    log_debug("closing library handle");
    if (nfq_close(g_nfq_h) != 0) {
        log_error("error during nfq_close()");
        return -1;
    }

    return 0;
}

int add_iptables_rules()
{
    char cmd[1024];
    // discard incoming ICMP packet, otherwise there will be socker error "No route to host"
    sprintf(cmd, "iptables -A INPUT -p icmp -j DROP");
    system(cmd);
    if (opt_protect_http_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -A INPUT -p tcp --sport 80 --tcp-flags RST RST -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -A INPUT -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing HTTP 'GET ' request
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m u32 --u32 '0>>22&0x3C@ 12>>26&0x3C@ 0=0x47455420' -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing HTTP 'POST' request
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m u32 --u32 '0>>22&0x3C@ 12>>26&0x3C@ 0=0x504F5354' -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // intercept incoming HTTP 'HTTP' response
        sprintf(cmd, "iptables -A INPUT -p tcp --sport 80 --tcp-flags SYN,ACK,RST ACK -m u32 --u32 '0>>22&0x3C@ 12>>26&0x3C@ 0=0x48545450' -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
    }
    if (opt_protect_dns_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -A INPUT -p tcp --sport 53 --tcp-flags RST RST -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport 53 --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -A INPUT -p tcp --sport 53 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport 53 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing DNS UDP request
        sprintf(cmd, "iptables -A OUTPUT -t raw ! -o lo -p udp --dport 53 -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming DNS UDP response
        sprintf(cmd, "iptables -A INPUT ! -i lo -p udp --sport 53 -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing DNS TCP request
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport 53 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming DNS TCP response
        sprintf(cmd, "iptables -A INPUT -p tcp --sport 53 --tcp-flags SYN,ACK,RST ACK -m length --length 80:0xffff -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
    }
    if (opt_protect_vpn_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -A INPUT -p tcp --sport %d --tcp-flags RST RST -j NFQUEUE --queue-num %d", opt_vpn_port, NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_vpn_port, MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -A INPUT -p tcp --sport %d --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", opt_vpn_port, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        //sprintf(cmd, "iptables -A OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", opt_vpn_port, MARK, NF_QUEUE_NUM);
        //system(cmd);
        // monitor outgoing VPN packets (TODO: intercept less packet)
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_vpn_port, MARK, NF_QUEUE_NUM);
        system(cmd);
    }
    if (opt_protect_tor_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -A INPUT -p tcp --sport %d --tcp-flags RST RST -j NFQUEUE --queue-num %d", opt_tor_port, NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_tor_port, MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -A INPUT -p tcp --sport %d --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", opt_tor_port, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        //sprintf(cmd, "iptables -A OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", opt_tor_port, MARK, NF_QUEUE_NUM);
        //system(cmd);
        // monitor outgoing VPN packets (TODO: intercept less packet)
        sprintf(cmd, "iptables -A OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_tor_port, MARK, NF_QUEUE_NUM);
        system(cmd);
    }
    return 0;
}

int remove_iptables_rules()
{
    char cmd[1024];
    // discard incoming ICMP packet, otherwise there will be socker error "No route to host"
    sprintf(cmd, "iptables -D INPUT -p icmp -j DROP");
    system(cmd);
    if (opt_protect_http_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -D INPUT -p tcp --sport 80 --tcp-flags RST RST -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -D INPUT -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing HTTP 'GET ' request
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m u32 --u32 '0>>22&0x3C@ 12>>26&0x3C@ 0=0x47455420' -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing HTTP 'POST' request
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport 80 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m u32 --u32 '0>>22&0x3C@ 12>>26&0x3C@ 0=0x504F5354' -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // intercept incoming HTTP 'HTTP' response
        sprintf(cmd, "iptables -D INPUT -p tcp --sport 80 --tcp-flags SYN,ACK,RST ACK -m u32 --u32 '0>>22&0x3C@ 12>>26&0x3C@ 0=0x48545450' -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
    }
    if (opt_protect_dns_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -D INPUT -p tcp --sport 53 --tcp-flags RST RST -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport 53 --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -D INPUT -p tcp --sport 53 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport 53 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing DNS UDP request
        sprintf(cmd, "iptables -D OUTPUT -t raw ! -o lo -p udp --dport 53 -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming DNS UDP response
        sprintf(cmd, "iptables -D INPUT ! -i lo -p udp --sport 53 -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing DNS TCP request
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport 53 --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -j NFQUEUE --queue-num %d", MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming DNS TCP response
        sprintf(cmd, "iptables -D INPUT -p tcp --sport 53 --tcp-flags SYN,ACK,RST ACK -m length --length 80:0xffff -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
        system(cmd);
    }
    if (opt_protect_vpn_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -D INPUT -p tcp --sport %d --tcp-flags RST RST -j NFQUEUE --queue-num %d", opt_vpn_port, NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_vpn_port, MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -D INPUT -p tcp --sport %d --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", opt_vpn_port, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        //sprintf(cmd, "iptables -D OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", opt_vpn_port, MARK, NF_QUEUE_NUM);
        //system(cmd);
        // monitor outgoing VPN packets (TODO: intercept less packet)
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_vpn_port, MARK, NF_QUEUE_NUM);
        system(cmd);
    }
    if (opt_protect_tor_protocol) {
        // monitor incoming RST
        sprintf(cmd, "iptables -D INPUT -p tcp --sport %d --tcp-flags RST RST -j NFQUEUE --queue-num %d", opt_tor_port, NF_QUEUE_NUM);
        system(cmd);
        // monitor outgoing SYN
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK SYN -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_tor_port, MARK, NF_QUEUE_NUM);
        system(cmd);
        // monitor incoming SYN-ACK
        sprintf(cmd, "iptables -D INPUT -p tcp --sport %d --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", opt_tor_port, NF_QUEUE_NUM);
        system(cmd);
        // intercept outgoing ACK
        //sprintf(cmd, "iptables -D OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -m length --length 0:80 -j NFQUEUE --queue-num %d", opt_tor_port, MARK, NF_QUEUE_NUM);
        //system(cmd);
        // monitor outgoing VPN packets (TODO: intercept less packet)
        sprintf(cmd, "iptables -D OUTPUT -p tcp --dport %d --tcp-flags SYN,ACK,RST ACK -m mark ! --mark %d -j NFQUEUE --queue-num %d", opt_tor_port, MARK, NF_QUEUE_NUM);
        system(cmd);
    }
    return 0;
}

// caching thread entry function 
void* cache_main(void *arg)
{
    int ret;
    ret = cache_main_loop();
    if (ret < 0) {
        log_error("Caching thread failed.");
    } else {
        log_info("Caching thread exited.");
    }
    return NULL;
}

// DNS proxy thread entry function 
void* dns_main(void *arg)
{
    int ret;
    ret = dns_proxy_loop();
    if (ret < 0) {
        log_error("DNS proxy failed.");
    } else {
        log_info("DNS proxy exited.");
    }
    return NULL;
}

// Feedback thread entry function 
void* feedback_main(void *arg)
{
    while (1)
    {
        sleep(600); // sleep 1min
        upload_log();
    }
    return NULL;
}

// Print debug info periodically 
void* debug_main(void *arg)
{
    while (1)
    {
        sleep(10);
        host_info_cache_summary();
        host_info_cache_dump();
        //conn_info_cache_summary();
        //conn_info_cache_dump();
    }
    return NULL;
}

void initialize()
{
    time_t now = time(NULL);

    srand(now);

    startup_ts = now;

    if (init_log() == -1) {
        fprintf(stderr, "Failed to initialzie log module.\n");
        exit(EXIT_FAILURE);
    }

    int ver = read_version();
    if (ver < VERSION) {
        log_info("Previous version %d, current version %d", ver, VERSION); 
        // this is a version update! 
        if (need_to_delete_redis_db) {
            log_info("Deleting redis DB due to version update.");
            delete_redis_db();
        }
    }
    else
        log_info("Current version: %d", VERSION);
    write_version(VERSION);

    start_redis_server();

    if (init_socket() == -1) {
        log_error("Failed to initialize socket module.");
        exit(EXIT_FAILURE);
    }

    log_debug("Adding iptables rules.");
    if (add_iptables_rules() == -1) {
        log_error("Failed to add iptables rules.");
        exit(EXIT_FAILURE);
    }

    register_signal_handlers();

    if (setup_nfq() == -1) {
        log_error("unable to setup netfilter_queue");
        exit(EXIT_FAILURE);
    }

    log_debug("Init DNS client.");
    if (init_dns_cli() == -1) {
        log_error("Failed to initialize DNS module");
        exit(EXIT_FAILURE);
    }

    log_debug("Init ev watchers.");
    init_ev_watchers();

    // Begin to intercept packets 
    //if (setup_strategy() == -1) {
    //    log_error("Failed to setup strategy");
    //    exit(EXIT_FAILURE);
    //}
    
    log_debug("Loading TTL from file.");
    load_ttl_from_file("ttl");

    // start a debug thread
    //pthread_t thread_dbg;
    //if (pthread_create(&thread_dbg, NULL, debug_main, NULL) != 0) {
    //    log_error("Fail to create debug thread.");
    //    exit(EXIT_FAILURE);
    //}

    // start a thread to handle communications with redis
    pthread_t thread_cache;
    if (pthread_create(&thread_cache, NULL, cache_main, NULL) != 0){
        log_error("Fail to create caching thread.");
        exit(EXIT_FAILURE);
    }
    
    // start the DNS proxy thread
    pthread_t thread_dns;
    if (pthread_create(&thread_dns, NULL, dns_main, NULL) != 0){
        log_error("Fail to create DNS thread.");
        exit(EXIT_FAILURE);
    }

    // Uploading diagnostic log is disabled. (2017.4.26) 
    // start a thread to send feedback log
    //pthread_t thread_fb;
    //if (pthread_create(&thread_fb, NULL, feedback_main, NULL) != 0){
    //    log_error("Fail to create feedback thread.");
    //    exit(EXIT_FAILURE);
    //}
}

void cleanup()
{
    save_ttl_to_redis();

    remove_iptables_rules();

    teardown_nfq();

    stop_redis_server();

    // Uploading diagnostic log is disabled. (2017.4.26) 
    //upload_log(); //TODO: resolve the conflict between the main and feedback thread
}

/* Process UDP packets 
 * Return 0 to accept packet, otherwise to drop packet
 */
int process_udp_packet(struct mypacket *packet, char inout)
{
    int i, ret;
    struct myiphdr *iphdr = packet->iphdr;
    struct myudphdr *udphdr = packet->udphdr;

    char sip[16], dip[16];
    ip2str(iphdr->saddr, sip);
    ip2str(iphdr->daddr, dip);

    unsigned short sport, dport;
    sport = ntohs(udphdr->uh_sport);
    dport = ntohs(udphdr->uh_dport);
    //log_debug("[UDP] This packet goes from %s:%d to %s:%d", sip, sport, dip, dport);

    struct fourtuple fourtp;
    fourtp.saddr = iphdr->saddr;
    fourtp.daddr = iphdr->daddr;
    fourtp.sport = udphdr->uh_sport;
    fourtp.dport = udphdr->uh_dport;

    if (dport == 53 || sport == 53) {
        // Parse DNS header
        struct mydnshdr *dnshdr = (struct mydnshdr*)packet->payload;
        unsigned short txn_id = ntohs(dnshdr->txn_id);
        int qdcount = ntohs(dnshdr->questions);
        char qname[MAX_QNAME_LEN];
        if (qdcount > 0) {
            int flag = 0; 
            //log_debug("Questions: %d", qdcount);
            unsigned char *ptr = (unsigned char *)(dnshdr + 1);
            for (i = 0; i < qdcount; i++) {
                struct mydnsquery query;
                int j = 0, l;
                while (1) {
                    for (l = *ptr++; l != 0; l--) {
                        query.qname[j++] = *ptr++;
                        if (j >= MAX_QNAME_LEN) {
                            while (*ptr != 0) ptr++;
                            break;
                        }
                    }
                    if (*ptr == 0) {
                        query.qname[j] = 0;
                        ptr++;
                        break;
                    }
                    query.qname[j++] = '.';
                }
                query.qtype = (ptr[0] << 8) + ptr[1];
                query.qclass = (ptr[2] << 8) + ptr[3];
                
                log_debug("DNS Query: %s %d %d", query.qname, query.qtype, query.qclass);

                // save the first query name for later usage 
                if (i == 0) {
                    qname[0] = 0;
                    strncat(qname, query.qname, MAX_QNAME_LEN - 1);
                }

                // check if qname in blacklist 
                if (is_poisoned_domain(qname))
                    flag = 1;
            }

            if (dport == 53) {
                // Process outgoing DNS requests
                log_debug("[UDP] Sent a DNS request from %s:%d to %s:%d.", sip, sport, dip, dport);

                if (opt_protect_dns_protocol == 1 && 
                        (opt_dns_only_blacklisted == 0 || opt_dns_only_blacklisted == 1 && flag)) {
                    log_debug("Redirecting to TCP.");
                    log_debugv("[EVAL] DNS TCP request %d", txn_id);

                    // Tell the caching thread to cache the request
                    // use DNS transaction ID and first query name as unique ID
                    // transaction ID alone may cause collision 
                    cache_dns_udp_request(txn_id, qname, &fourtp);

                    // send the request over TCP 
                    ret = send_dns_req(packet->payload, packet->payload_len);
                    if (ret == 0) {
                        // drop the packet 
                        return -1;
                    } else {
                        log_error("DNS redirect failed.");
                    }
                    //send_udp2(packet);
                }
                else {
                    log_debugv("[EVAL] DNS UDP request %d", txn_id);
                }
            }
            else if (sport == 53) {
                if (opt_protect_dns_protocol == 1 && 
                        (opt_dns_only_blacklisted == 0 || opt_dns_only_blacklisted == 1 && flag)) {
                    // the response must be sent by ourself
                    return 0;
                }
                // Process incoming DNS responses
                log_debug("[UDP] Got a DNS response from %s:%d to %s:%d.", sip, sport, dip, dport);
                log_debugv("[EVAL] DNS UDP response %d", txn_id);

                // Tell the caching thread to process the dns udp response
                process_dns_udp_response(txn_id, qname, &fourtp, iphdr->ttl);
            }

        }
        else {
            log_error("[UDP] DNS request has 0 question.");
        }

    }

    return 0;
}

/* Process TCP packets
 * Return 0 to accept packet, otherwise to drop packet 
 */
int process_tcp_packet(struct mypacket *packet, char inout)
{
    int ret = 0;
    struct myiphdr *iphdr = packet->iphdr;
    struct mytcphdr *tcphdr = packet->tcphdr;
    unsigned char *payload = packet->payload;

    char sip[16], dip[16];
    ip2str(iphdr->saddr, sip);
    ip2str(iphdr->daddr, dip);

    unsigned short sport, dport;
    //unsigned int seq, ack;
    sport = ntohs(tcphdr->th_sport);
    dport = ntohs(tcphdr->th_dport);
    //seq = tcphdr->th_seq;
    //ack = tcphdr->th_ack;
    log_debug("[TCP] This packet goes from %s:%d to %s:%d", sip, sport, dip, dport);
    log_debug("TCP flags: %s", tcp_flags(tcphdr->th_flags));

    struct fourtuple fourtp;
    fourtp.saddr = iphdr->saddr;
    fourtp.daddr = iphdr->daddr;
    fourtp.sport = tcphdr->th_sport;
    fourtp.dport = tcphdr->th_dport;

    // for testing uni-directional packet forwarding to bypass IP blocking 
    //if (dport == 80 && is_blocked_ip(dip)) {
    //    log_debug("Going to forward that packet!!!");
    //    unsigned int newlen = packet->len + 4;
    //    char *newpkt = (char*)malloc(newlen);
    //    memcpy(newpkt, packet->data, packet->len);
    //    *(u_int32_t*)(newpkt + packet->len) = iphdr->daddr;
    //    ip_hdr(newpkt)->daddr = str2ip(PACKET_FORWARDER);
    //    send_raw(newpkt, newlen);
    //    log_debug("sent!!!");
    //    return 0;
    //}

    if (tcphdr->th_flags == TCP_SYN) {
        // Processing outgoing SYN packet. 

        // Uploading diagnostic log is disabled. (2017.9.1) 
        //if (strcmp(dip, FEEDBACK_SERVER_IP) == 0)
        //    return 0;
        

        // choose a strategy for the newly created connection
        int sid = choose_strategy_by_historical_result(iphdr->daddr);
        log_debug("Using strategy %s", g_strats[sid].name);
        set_sid(&fourtp, sid);
        //cache_strategy(&fourtp, sid);

        if (g_strats[sid].process_syn) {
            ret = g_strats[sid].process_syn(packet);
#ifndef EVALUATION
            if (ret) {
                need_evaluation(&fourtp);
            }
#endif
        }
    }
    if (tcphdr->th_flags == (TCP_SYN | TCP_ACK)) {
        // Got a SYN-ACK from server

        // send an ACK with 1 TTL to make home router happy 
        if (opt_inject_ack_with_one_ttl)
            send_ACK_with_one_ttl(dip, dport, sip, sport, tcphdr->th_ack, htonl(ntohl(tcphdr->th_seq)+1));

        struct fourtuple reverse_fourtp;
        reverse_fourtp.saddr = iphdr->daddr;
        reverse_fourtp.daddr = iphdr->saddr;
        reverse_fourtp.sport = tcphdr->th_dport;
        reverse_fourtp.dport = tcphdr->th_sport;

        int sid = get_sid(&reverse_fourtp);
        if (sid >= 0) {
            if (get_ttl(iphdr->saddr) == 0) {
                // if TTL hasn't been initialized 
                // find initial TTL from SYN/ACK packet
                int ttl = choose_appropriate_ttl(iphdr->ttl);
                set_ttl(iphdr->saddr, ttl);
            }
            if  (g_strats[sid].process_synack) {
                ret = g_strats[sid].process_synack(packet);
#ifndef EVALUATION
                if (ret) {
                    need_evaluation(&reverse_fourtp);
                }
#endif
            }
        }
        else if (sid == -1) {
            ret = process_synack_for_ttl_probing(packet);
        }

        //if (opt_inject_syn_and_syn_ack_with_one_ttl)
        //    send_one_ttl_SYN_and_SYN_ACK(dip, dport, sip, sport, tcphdr->th_ack, tcphdr->th_seq);
    } 
    else if ((tcphdr->th_flags & TCP_ACK) && 
        !(tcphdr->th_flags & (TCP_SYN | TCP_RST))) {
        // ignore ACK packets without payload 
        if (packet->payload_len == 0) 
            return 0;

        if (dport == 80) {
            if ((payload[0] == 'G' && payload[1] == 'E' && 
                 payload[2] == 'T' && payload[3] == ' ') ||
                (payload[0] == 'P' && payload[1] == 'O' && 
                 payload[2] == 'S' && payload[3] == 'T' && 
                 payload[4] == ' ')) {
                // Got a outgoing HTTP request 
                log_debug("[TCP] Sent a HTTP request from %s:%d to %s:%d.", sip, sport, dip, dport);
                int i, j, k, l;
                
                //char req_line[1000];
                //for (i = 0; i < 1000; i++) {
                //    if (payload[i] == '\r' || payload[i] == '\n') {
                //        req_line[i] = 0;
                //        break;
                //    }
                //    req_line[i] = payload[i];
                //}
                
                // Generate the HTTP request line. Format: GET/POST domain/url. e.g. GET www.google.com/index.php
                char req_line2[1000];
                // copy GET/POST 
                for (i = 0; payload[i] != ' ' && i < packet->payload_len; i++) {
                    req_line2[i] = payload[i];
                }
                req_line2[i++] = ' ';
                k = i; 
    
                // find Host field
                for (j = i; j < packet->payload_len; j++) {
                    if (payload[j] == 'H' && payload[j+1] == 'o' &&
                            payload[j+2] == 's' && payload[j+3] == 't' &&
                            payload[j+4] == ':' && (payload[j-1] == '\r' || payload[j-1] == '\n')) {
                        j += 5;
                        // copy Host value 
                        while (payload[j] == ' ') j++;
                        for (l = 0; l < 99 && j+l < packet->payload_len; l++) {
                            if (payload[j+l] == '\r' || payload[j+l] == '\n')
                                break;
                            req_line2[k++] = payload[j+l];
                        }
                        break;
                    }
                }

                // copy the rest of request line 
                for (; i < 900 && i < packet->payload_len; i++) {
                    if (payload[i] == '\r' || payload[i] == '\n') {
                        break;
                    }
                    req_line2[k++] = payload[i];
                }
                req_line2[k] = 0;
    
                log_debug("[TCP] %s", req_line2); 

                int sid = get_sid(&fourtp);
                if (sid >= 0 && g_strats[sid].process_request) {
                    ret = g_strats[sid].process_request(packet);
#ifndef EVALUATION
                    if (ret) {
                        need_evaluation(&fourtp);
                    }
#endif
                }
#ifdef EVALUATION
                if (strstr(req_line2, "ultrasurf") || strstr(req_line2, "goodword")) {
                    need_evaluation(&fourtp);
                }
#endif

                cache_http_request(&fourtp, req_line2);
            }
        }
        else if (sport == 80) {
            if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') {
                // Got a incoming HTTP response 
                log_debug("[TCP] Got a HTTP response from %s:%d to %s:%d.", sip, sport, dip, dport);
                process_http_response(&fourtp, tcphdr->th_seq, iphdr->ttl);
            }
        }
        else if (dport == 53) {
            // Got a DNS request over TCP 
            log_debug("[TCP] Sent a DNS request from %s:%d to %s:%d.", sip, sport, dip, dport);

            int sid = get_sid(&fourtp);
            if (sid >= 0 && g_strats[sid].process_request) {
                ret = g_strats[sid].process_request(packet);
#ifndef EVALUATION
                if (ret) {
                    need_evaluation(&fourtp);
                }
#endif
            }

            cache_dns_tcp_request(&fourtp);
        }
        else if (sport == 53) {
            // Got a DNS response over TCP, maybe triggered by our app, or maybe not 
            log_debug("[TCP] Got a DNS response from %s:%d to %s:%d.", sip, sport, dip, dport);
            // parse the DNS response to get the first qname 
            const unsigned char *dns_payload = packet->payload + 2;
            struct mydnshdr *dnshdr = (struct mydnshdr*)dns_payload;
            unsigned short txn_id = htons(dnshdr->txn_id);
            int qdcount = ntohs(dnshdr->questions);
            char qname[MAX_QNAME_LEN];
            if (qdcount > 0) {
                //log_debug("Questions: %d", qdcount);
                unsigned char *ptr = (unsigned char *)(dnshdr + 1);
                {
                    struct mydnsquery query;
                    int j = 0, l;
                    while (1) {
                        for (l = *ptr++; l != 0; l--) {
                            query.qname[j++] = *ptr++;
                            if (j >= MAX_QNAME_LEN) {
                                while (*ptr != 0) ptr++;
                                break;
                            }
                        }
                        if (*ptr == 0) {
                            query.qname[j] = 0;
                            ptr++;
                            break;
                        }
                        query.qname[j++] = '.';
                    }
                    query.qtype = (ptr[0] << 8) + ptr[1];
                    query.qclass = (ptr[2] << 8) + ptr[3];
                    
                    log_debug("DNS Query: %s %d %d", query.qname, query.qtype, query.qclass);
    
                    // use the first query to calc hash 
                    qname[0] = 0;
                    strncat(qname, query.qname, MAX_QNAME_LEN - 1);
                }

                // Tell the caching thread to process the dns udp response
                // use DNS transaction ID and first query name as unique ID
                // transaction ID alone may cause collision 
                process_dns_tcp_response(txn_id, qname, &fourtp, tcphdr->th_seq, iphdr->ttl, packet->payload, packet->payload_len);

            }
        }
        else if (dport == opt_vpn_port) {
            // outgoing packet
            int sid = get_sid(&fourtp);
            if (sid >= 0 && g_strats[sid].process_request) {
                ret = g_strats[sid].process_request(packet);
                if (ret) {
                    if (opt_inject_syn_and_syn_ack_with_one_ttl == 1)
                        send_one_ttl_SYN(sip, sport, dip, dport, tcphdr->th_seq);
                    else if (opt_inject_syn_and_syn_ack_with_one_ttl == 2)
                        send_one_ttl_SYN_and_SYN_ACK(sip, sport, dip, dport, tcphdr->th_seq, tcphdr->th_ack);
                }
            }
        }
        else if (sport == opt_vpn_port) {
            // incomine packet
        }
        else if (dport == opt_tor_port) {
            // outgoing packet
            int sid = get_sid(&fourtp);
            if (sid >= 0 && g_strats[sid].process_request) {
                ret = g_strats[sid].process_request(packet);
                if (ret) {
                    if (opt_inject_syn_and_syn_ack_with_one_ttl == 1)
                        send_one_ttl_SYN(sip, sport, dip, dport, tcphdr->th_seq);
                    else if (opt_inject_syn_and_syn_ack_with_one_ttl == 2)
                        send_one_ttl_SYN_and_SYN_ACK(sip, sport, dip, dport, tcphdr->th_seq, tcphdr->th_ack);
                }
            }
        }
        else if (sport == opt_tor_port) {
            // incomine packet
        }
        else {
            // TODO: for all other protocols. This branch is a piece of temporary code, should be re-write.
            if (inout == 0) {
                // incoming packet
                log_debug("this is an incoming packet.");
            }
            else {
                // outgoing packet
                log_debug("this is an outgoing packet.");
                int sid = get_sid(&fourtp);
                if (sid >= 0 && g_strats[sid].process_request) {
                    ret = g_strats[sid].process_request(packet);
                    if (ret) {
                        if (opt_inject_syn_and_syn_ack_with_one_ttl == 1)
                            send_one_ttl_SYN(sip, sport, dip, dport, tcphdr->th_seq);
                        else if (opt_inject_syn_and_syn_ack_with_one_ttl == 2)
                            send_one_ttl_SYN_and_SYN_ACK(sip, sport, dip, dport, tcphdr->th_seq, tcphdr->th_ack);
                    }
                }
            }
        }
    }
    else if (tcphdr->th_flags & TCP_RST) {
        // Got an incoming RST 
        log_debug("[TCP] Got an incoming RST from %s:%d to %s:%d.", sip, sport, dip, dport);

        process_incoming_RST(packet);
    }

    return ret;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, 
              struct nfq_data *nfa, void *data)
{
    //log_debug("entering callback");
    //char buf[1025];
    //nfq_snprintf_xml(buf, 1024, nfa, NFQ_XML_ALL);
    //log_debug("%s", buf);
    
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        log_error("nfq_get_msg_packet_hdr failed");
        return -1;
    }
    u_int32_t id = ntohl(ph->packet_id);
    //log_debug("packet id: %d", id);
    
    char inout = nfq_get_outdev(nfa) ? 1 : 0; // 0 - in, 1 - out

    // get data (IP header + TCP header + payload)
    unsigned char *pkt_data;
    int plen = nfq_get_payload(nfa, &pkt_data);
    g_modified = 0;
    //if (plen >= 0)
    //    log_debug("payload_len=%d", plen);
    //hex_dump(pkt_data, plen);

    struct mypacket packet;
    packet.data = pkt_data;
    packet.len = plen;
    packet.iphdr = ip_hdr(pkt_data);
    
    // parse ip
    //char sip[16], dip[16];
    //ip2str(packet.iphdr->saddr, sip);
    //ip2str(packet.iphdr->daddr, dip);
    //log_debug("This packet goes from %s to %s.", sip, dip);
    //log_debugv("This packet goes from %s to %s.", sip, dip);

    if (is_ip_in_whitelist(packet.iphdr->saddr) || is_ip_in_whitelist(packet.iphdr->daddr)) {
        nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return 0;
    }

    int ret = 0;

    switch (packet.iphdr->protocol) {
        case 6: // TCP
            packet.tcphdr = tcp_hdr(pkt_data);
            packet.payload = tcp_payload(pkt_data);
            packet.payload_len = packet.len - packet.iphdr->ihl*4 - packet.tcphdr->th_off*4;
            //show_packet(&packet);
            ret = process_tcp_packet(&packet, inout);
            break;
        case 17: // UDP
            packet.udphdr = udp_hdr(pkt_data);
            packet.payload = udp_payload(pkt_data);
            packet.payload_len = packet.len - packet.iphdr->ihl*4 - 8;
            if (packet.payload_len != ntohs(packet.udphdr->uh_ulen) - 8)
                log_warn("UDP payload length unmatch! %d <> %d", packet.payload_len, ntohs(packet.udphdr->uh_ulen) - 8);
            //show_packet(&packet);
            ret = process_udp_packet(&packet, inout);
            break;
        default:
            log_error("Invalid protocol: %d", packet.iphdr->protocol);
    }
    
    int verdict_ret;
    if (ret == 0) {
        if (g_modified) 
        {
            log_warn("Packet Modified.");
            //if (packet.iphdr->protocol == 6) {
            //    packet.tcphdr->th_sum = tcp_checksum(packet.data, ntohs(packet.iphdr->tot_len));
            //}
            //packet.iphdr->check = ip_checksum(packet.data, packet.len);
            verdict_ret = nfq_set_verdict(qh, id, NF_ACCEPT, packet.len, packet.data);
            //log_info("VERDICT MODIFIED ACCEPT");
        }
        else {
            verdict_ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            //log_info("VERDICT ACCEPT");
        }
    }
    else if (ret == 1) {
        usleep(DELAY_AFTER_PACKET_INJECTION);
        verdict_ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        //log_info("VERDICT DELAYED ACCEPT");
    }
    else {
        verdict_ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        //log_info("VERDICT DROP");
    }
        
    // return <0 to stop processing
    return verdict_ret;
}

void setup_daemon()
{
    pid_t pid, sid;

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed.\n");
        exit(EXIT_FAILURE);
    }

    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);

    sid = setsid();
    if (sid < 0) {
        fprintf(stderr, "setsid failed.\n");
        exit(EXIT_FAILURE);
    }

    //if (chdir("/") < 0)
    //    exit(EXIT_FAILURE);

    close(STDIN_FILENO);
    //close(STDOUT_FILENO);
    //close(STDERR_FILENO);
}


int main(int argc, char **argv)
{
#ifdef EVALUATION
    if (argc != 2) {
        printf("INTANG is compiled in Evalution Mode. Usage:\n%s <sid>\n", argv[0]);
        return 0;
    }
#endif

    //TODO: use option parser
    int i;
    if (argc >= 2) {
        if (strcmp(argv[1], "-h") == 0) {
            // print strategy list
            printf("Strategies:\n");
            for (i = 0; i < g_strat_num; i++) {
                printf("%d\t%s\n", i, g_strats[i].name);
            }
            return 0;
        }

        int sid = atoi(argv[1]);
        if (sid >= 0 && sid < g_strat_num) {
            for (i = 0; i < g_strat_num; i++) {
                g_strat_weights[i] = 0;
            }
            g_strat_weights[sid] = 10;
            printf("Using strategy %d, %s.\n", sid, g_strats[sid].name);
        }
        else {
            printf("Invalid SID %d.\n", sid);
            return -1;
        }
    }
    
    // check for root privilege
    uid_t uid=getuid(), euid=geteuid();
    if (euid != 0) {
        printf("This program needs root privilege to work.\n");
        exit(EXIT_FAILURE);
    } 

    // create the application directory if not exist
    mkdir(APP_DIR, 0755);

    //setlogmask(LOG_UPTO(LOG_NOTICE));
    //openlog("intangd", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_LOCAL1);

    // turns the process into a daemon 
    setup_daemon();

    printf("Daemon has started.\n");
    if (opt_logging_to_file) {
        printf("The logs can be found in %s\n", LOG_FILE);
    }

    // now the process turns into a daemon process

    // initialization
    initialize();

#ifdef TEST
    test_main();
#else
    // Main loop
    int rv;
    char buf[65536];

    while ((rv = recv(g_nfq_fd, buf, sizeof(buf), 0)) && rv >= 0) {
        //log_debugv("pkt received");
        nfq_handle_packet(g_nfq_h, buf, rv);
    }
    log_debug("rv = %d. errno: %d. %s", rv, errno, strerror(errno));

    log_debug("Running out of the loop.");
#endif
    cleanup();
    log_info("Daemon exited.");

    return 0;
}


