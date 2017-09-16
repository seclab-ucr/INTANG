#!/usr/bin/env python

import random
import sys

from scapy.all import TCP, IP, sr1


ip = sys.argv[1]

#print("Measuring %s..." % ip)
for ttl in range(5, 64):
    #print("Using ttl %d." % ttl) 
    #sport = ttl + 20000
    sport = random.randint(10000, 60000)
    seq = random.getrandbits(32)
    syn = IP(dst=ip, ttl=ttl, flags='DF')/TCP(sport=sport, dport=80, flags='S', seq=seq, options=[('MSS', 1460)])
    synack = sr1(syn, timeout=3, verbose=False)
    if synack and TCP in synack and synack[TCP].flags == 0x012:
        print("%s,%d" % (ip, ttl))
        break

