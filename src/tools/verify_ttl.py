#!/usr/bin/env python

import sys
from socket import ntohs
from tools import *

if len(sys.argv) == 1:
    log_file = "/var/log/intangd.log"
else:
    log_file = sys.argv[1]

ttl_all = {}

tot = 0

f = open(log_file, 'r')

for line in f:
    if '[TTL Probing]' in line:
        line = line[:-2]
        parts = line.split()
        dip = parts[9]
        ttl = int(parts[11])
        #print("IP: %s, TTL: %d" % (dip, ttl))
        if dip not in ttl_all:
            ttl_all[dip] = {}
        if ttl not in ttl_all[dip]:
            ttl_all[dip][ttl] = 0
        ttl_all[dip][ttl] += 1
        tot += 1


for dip in ttl_all.keys():
    print("%s: %s" % (dip, ttl_all[dip]))

print("Total: %d" % tot)

