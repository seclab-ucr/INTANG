#!/usr/bin/env python

import sys
from socket import ntohs
from tools import *

if len(sys.argv) == 1:
    log_file = "/var/log/intangd.log"
else:
    log_file = sys.argv[1]

rst_attack = {}

stats = {}
cases = {}


f = open(log_file, 'r')

for line in f:
    line = line[:-1]
    if 'Triggered Reset Attack' in line:
        pos = line.find('Attack!')
        pos2 = line.find('.', pos)
        fourtp_sid = line[pos + 7:pos2]
        saddr, sport, daddr, dport, sid = fourtp_sid.split('_')
        daddr = int(daddr)
        sid = int(sid)
        pos = line.find('LAST REQ:')
        url = line[pos + 10:]
        if url not in rst_attack:
            rst_attack[url] = {'cnt':0}
        rst_attack[url]['cnt'] += 1
        if daddr not in rst_attack[url]:
            rst_attack[url][daddr] = 0
        rst_attack[url][daddr] += 1
    elif 'STRATEGY SUC' in line or 'STRATEGY FAILED 1' in line or 'STRATEGY FAILED 2' in line:
        if 'STRATEGY SUC' in line:
            pos = line.find('EEDED.')
            fourtp_sid = line[pos + 7:]
            res = 'succ'
        elif 'STRATEGY FAILED 1' in line:
            pos = line.find('RESPONSE.')
            fourtp_sid = line[pos + 10:]
            res = 'fail1'
        elif 'STRATEGY FAILED 2' in line:
            pos = line.find('ATTACK.')
            fourtp_sid = line[pos + 8:]
            res = 'fail2'

        saddr, sport, daddr, dport, sid = fourtp_sid.split('_')
        daddr = int(daddr)
        sid = int(sid)
        if sid not in stats:
            stats[sid] = {'succ': 0, 'fail1': 0, 'fail2': 0}
        stats[sid][res] += 1
        if sid not in cases:
            cases[sid] = {'succ': {}, 'fail1': {}, 'fail2': {}}
        if daddr not in cases[sid][res]:
            cases[sid][res][daddr] = 0
        cases[sid][res][daddr] += 1

# output
print("*** Strategy Stats ***")
print("Strategy\tSucc\tFail1\tFail2\tSucc Rate")
for sid in stats.keys():
    if stats[sid]['succ'] + stats[sid]['fail2'] != 0:
        print("%d\t\t%d\t%d\t%d\t%f" % (sid, stats[sid]['succ'], stats[sid]['fail1'], stats[sid]['fail2'], float(stats[sid]['succ']) / (stats[sid]['succ'] + stats[sid]['fail2'])))

for sid in range(15):
    if sid not in cases: continue
    if 'fail1' in cases[sid] and cases[sid]['fail1']:
        print("*** Strategy %d: Fail 1 ***" % sid)
        sorted_f1 = sorted(cases[sid]['fail1'], key=cases[sid]['fail1'].get, reverse=True)
        for c in sorted_f1[:10]:
            print("%d\t%s" % (cases[sid]['fail1'][c], ip2str(c)))

    if 'fail2' in cases[sid] and cases[sid]['fail2']:
        print("*** Strategy %d: Fail 2 ***" % sid)
        sorted_f2 = sorted(cases[sid]['fail2'], key=cases[sid]['fail2'].get, reverse=True)
        for c in sorted_f2[:10]:
            print("%d\t%s" % (cases[sid]['fail2'][c], ip2str(c)))
    print("*** Strategy %d: Succ Rate ***" % sid)
    daddr_list = []
    daddr_list += cases[sid]['succ']
    daddr_list += cases[sid]['fail1']
    daddr_list += cases[sid]['fail2']
    daddr_set = set(daddr_list)
    for daddr in daddr_set:
        succ = cases[sid]['succ'].get(daddr, 0)
        fail2 = cases[sid]['fail2'].get(daddr, 0)
        if succ + fail2 != 0:
            print("%s\t%f(%d/%d)" % (ip2str(daddr), (1-float(fail2)/(succ+fail2)), fail2, succ+fail2))

print("-------------------------------------------------------")

print("*** Reset Attacks ***")
print("Count\tURL")
rst_attack = sorted(rst_attack.items(), key=lambda x: x[1]['cnt'], reverse=True)
for key, value in rst_attack:
    print("%d\t%s" % (value['cnt'], key))
    #del value['cnt']
    #ips = sorted(value.items(), key=lambda x: x[1], reverse=True)
    #for ip, cnt in ips:
    #    print("* %s\t%d" % (ip2str(ip), cnt))


