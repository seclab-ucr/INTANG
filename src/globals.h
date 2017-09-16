
#ifndef __GLOBAL_H__
#define __GLOBAL_H__


#define APP_DIR "/usr/local/share/intangd/" 

#define LOG_FILE "/var/log/intangd.log"

#define NF_QUEUE_NUM 1

#define MARK 0x09

#define FEEDBACK_SERVER_IP "169.235.31.180"

#define FEEDBACK_SERVER_PORT 80

#define LOCAL_DNS_PORT 5305

#define DNS_BLACKLIST "dns_blacklist"

// if you are behind a NAT and your NAT may be closed by outgoing RST, you should fill in your NAT external IP and turn on opt_inject_fake_syn_and_syn_ack. 
#define NAT_EXT_IP "58.53.150.103"


#endif

