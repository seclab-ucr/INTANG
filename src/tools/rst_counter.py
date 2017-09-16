#!/usr/bin/env python

import sys

from scapy.all import sniff, TCP, IP

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

pcap_file = sys.argv[1]

rst_ttl = {}
rst_attack={}

fail2_count = 0


def output_packet(pkt):
    print("%s:%d-%s:%d %d %s" % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, pkt[IP].ttl, pkt[TCP].flags))


def process_pkt(pkt):
    global fail2_count
    #pkt.show()
    if TCP in pkt:
        if pkt[IP].dst == "169.235.31.180":
            flags = pkt[TCP].flags
            src = pkt[IP].src
            ttl = pkt[IP].ttl
            if flags == (RST | ACK):
                output_packet(pkt)
                if src not in rst_ttl:
                    rst_ttl[src] = (ttl, pkt.time)
                else:
                    if ttl != rst_ttl[src][0]:
                        print("TTL differ")
                        if pkt.time - rst_ttl[src][1] < 1:
                            print("in less than 1s")
                            if src not in rst_attack:
                                rst_attack[src] = pkt.time
                                fail2_count += 1
                                print("RST ATTACK.")
                                output_packet(pkt)
                            else:
                                if pkt.time - rst_attack[src] > 100:
                                    rst_attack[src] = pkt.time
                                    fail2_count += 1
                                    print("RST ATTACK.")
                                    output_packet(pkt)
                                else:
                                    print("still in 90s")
                        rst_ttl[src] = (ttl, pkt.time)


sniff(offline=pcap_file, prn=process_pkt, store=0)

print(fail2_count)

