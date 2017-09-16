#!/usr/bin/env python

import sys
import subprocess
import random

from multiprocessing import Pool
from time import sleep
from scapy.all import TCP, IP, sr1


MAX_PROC_NUM = 10

result = {}
ips = []

def measure_ttl(ip):
    #print("Measuring %s..." % ip)
    for ttl in range(5, 64):
        #print("Using ttl %d." % ttl) 
        #sport = ttl + 20000
        sport = random.randint(10000, 60000)
        seq = random.getrandbits(32)
        syn = IP(dst=ip, ttl=ttl, flags='DF')/TCP(sport=sport, dport=53, flags='S', seq=seq, options=[('MSS', 1460)])
        synack = sr1(syn, timeout=3, verbose=False)
        if synack and TCP in synack and synack[TCP].flags == 0x012:
            return ip, ttl
    return ip, 99

def save_result(param):
    ip, ttl = param
    result[ip] = ttl


pool = Pool(MAX_PROC_NUM)

f = open(sys.argv[1], 'r')

for line in f:
    line = line[:-1]
    #print(line)
    parts = line.split(',')
    ip = parts[2]
    ips.append(ip)

    pool.apply_async(measure_ttl, (ip,), callback=save_result)

f.close()

pool.close()
pool.join()
    
fo = open(sys.argv[2], 'w')

for ip in ips:
    fo.write("%s,%d\n" % (ip, result[ip]))

fo.close()
    
