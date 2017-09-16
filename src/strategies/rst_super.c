/*
 * Strategy implementation
 * .setup function:     Set up triggers, which listen to specific 
 *                      incoming or outgoing packets, and bind 
 *                      triggers to these events. 
 * .teardown function:  Unbind triggers.
 *
 */

#include "rst_super.h"

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


int x6_setup()
{
    char cmd[256];
    sprintf(cmd, "iptables -A INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x6_teardown()
{
    char cmd[256];
    sprintf(cmd, "iptables -D INPUT -p tcp -m multiport --sport 53,80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    system(cmd);

    return 0;
}

int x6_process_syn(struct mypacket *packet)
{
    return 0;
}

int x6_process_synack(struct mypacket *packet)
{
    return 0;
}

int x6_process_request(struct mypacket *packet)
{
    unsigned int rflags, dflags;
    rflags = INS_DISC_MD5 | INS_DISC_OLD_TIMESTAMP;
    dflags = INS_DISC_BAD_ACK_NUM | INS_DISC_MD5 | INS_DISC_OLD_TIMESTAMP;
    if (1) {
        rflags |= INS_DISC_SMALL_TTL;
    }
    if (1) {
        dflags |= INS_DISC_SMALL_TTL;
    }
    if (0) {
        rflags |= INS_DISC_BAD_TCP_CHECKSUM;
        dflags |= INS_DISC_BAD_TCP_CHECKSUM;
    }

    send_fake_RST(packet, rflags);
    usleep(20000);
    send_fake_RST(packet, rflags);
    usleep(20000);
    send_fake_RST(packet, rflags);
    usleep(20000);
    send_desync_data(packet, dflags);
    usleep(20000);
    send_desync_data(packet, dflags);
    usleep(20000);
    send_desync_data(packet, dflags);

    return 1;
}


