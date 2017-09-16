
#ifndef __DISCREPANCY_H__
#define __DISCREPANCY_H__

#include "protocol.h"
#include "socket.h"


// Insertion Packet Discrepancy
#define INS_DISC_SMALL_TTL          1
#define INS_DISC_BAD_TCP_CHECKSUM   (1 << 1)
#define INS_DISC_NO_TCP_FLAG        (1 << 2)
#define INS_DISC_BAD_ACK_NUM        (1 << 3)
#define INS_DISC_MD5                (1 << 4)
#define INS_DISC_OLD_TIMESTAMP      (1 << 5)


void send_insertion_packet(struct send_tcp_vars *vars, unsigned int flags);

void send_fake_SYN(struct mypacket *orig_packet, unsigned int flags);
void send_fake_FIN(struct mypacket *orig_packet, unsigned int flags);
void send_fake_RST(struct mypacket *orig_packet, unsigned int flags);
void send_fake_data(struct mypacket *orig_packet, unsigned int flags);
void send_fake_SYN_ACK(struct mypacket *orig_packet, unsigned int flags);
void send_desync_data(struct mypacket *orig_packet, unsigned int flags);

#endif

