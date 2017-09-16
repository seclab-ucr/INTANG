/*
 * Strategy implementation
 * .setup function:     Set up triggers, which listen to specific 
 *                      incoming or outgoing packets, and bind 
 *                      triggers to these events. 
 * .teardown function:  Unbind triggers.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "globals.h"
#include "socket.h"
#include "protocol.h"
#include "logging.h"



int x0_setup()
{
    //char cmd[256];
    //sprintf(cmd, "iptables -A INPUT -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    //system(cmd);

    return 0;
}

int x0_teardown()
{
    //char cmd[256];
    //sprintf(cmd, "iptables -D INPUT -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num %d", NF_QUEUE_NUM);
    //system(cmd);

    return 0;
}

int x0_process_syn(struct mypacket *packet)
{
    return 0;
}

int x0_process_synack(struct mypacket *packet)
{
    return 0;
}

int x0_process_request(struct mypacket *packet)
{
    return 0;
}


