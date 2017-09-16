#!/usr/bin/env python

import redis
import socket

from tools import *


class Processor(object):

    r = None

    def __init__(self):
        self.r = redis.StrictRedis(host='localhost', port=6389, db=0)

    def dump_dns_poisoning(self):
        dnsp = {}
        keys = self.r.keys('measure:dnsp:*')
        for k in keys:
            parts = k.split(':')
            domain = parts[2]
            v = self.r.get(k)
            if v:
                v = int(v)
            else:
                v = 1
            dnsp[domain] = int(v)

        # output
        print("*** DNS Poisoning ***")
        print("Count\tDomain")
        for domain in sorted(dnsp, key=dnsp.get, reverse=True):
            print("%d\t%s" % (dnsp[domain], domain))


    def dump_http_injection(self):
        httpi = {}
        keys = self.r.keys('measure:httpi:*')
        for k in keys:
            parts = k.split(':')
            ip = ip2str(int(parts[2]))
            req = parts[3]
            if not req: req = 'unknown'
            if ip not in httpi:
                httpi[ip] = {0:0}
            v = self.r.get(k)
            if v:
                v = int(v)
            else:
                v = 1
            httpi[ip][0] += v
            if req not in httpi[ip]:
                httpi[ip][req] = 0
            httpi[ip][req] += v

        # output
        print("*** HTTP Injection ***")
        print("IP\t\tTotal Count\tTotal URLs")
        for ip in sorted(httpi, key=httpi.get, cmp=lambda x,y: cmp(x[0], y[0]), reverse=True):
            print("%s\t\t%d\t%d" % (ip, httpi[ip][0], len(httpi[ip]) - 1))


    def dump_keywords(self):
        sites = {}
        keys = self.r.keys('measure:httprst:*')
        for k in keys:
            parts = k.split(':')
            ip = ip2str(int(parts[2]))
            req = parts[3]
            if not req: req = 'unknown'
            v = self.r.get(k)
            if v:
                v = int(v)
            else:
                v = 1
            if ip not in sites:
                sites[ip] = {}
            sites[ip][req] = v

        # output
        print("*** Reset Attacks ***")
        print("IP\t\tCount\tRequests")
        for ip in sites.keys():
            reqs = sorted(sites[ip], key=sites[ip].get, reverse=True)
            print("%s\t%d\t%s" % (ip, sites[ip][reqs[0]], cut(reqs[0], 80)))
            for req in reqs[1:]:
                print("\t\t%d\t%s" % (sites[ip][req], cut(req, 80)))


    def dump_stats(self):
        stats = {}
        cases = {}
        keys = self.r.keys('strategy:stats:*')
        #print(res)
        for k in keys:
            parts = k.split(':')
            v = self.r.get(k)
            if v:
                v = int(v)
                sid = int(parts[2])
                dip = int(parts[3])
                if sid not in stats:
                    stats[sid] = {'succ':0, 'fail1':0, 'fail2a':0, 'fail2b': 0}
                res = parts[-1]
                stats[sid][res] += v

                if sid not in cases:
                    cases[sid] = {'succ':{}, 'fail1': {}, 'fail2a': {}, 'fail2b': {}}
                if dip not in cases[sid][res]:
                    cases[sid][res][dip] = 0
                cases[sid][res][dip] += v

        # output
        print("*** Strategy Stats ***")
        print("Strategy\tSucc\tFail1\tFail2a\tFail2b\tSucc Rate")
        for sid in stats.keys():
            if stats[sid]['succ'] + stats[sid]['fail2a'] +stats[sid]['fail2b']!= 0:
                print("%d\t\t%d\t%d\t%d\t%d\t%f" % (sid, stats[sid]['succ'], stats[sid]['fail1'], stats[sid]['fail2a'], stats[sid]['fail2b'], float(stats[sid]['succ']) / (stats[sid]['succ'] + stats[sid]['fail2a'] + stats[sid]['fail2b'])))

        for sid in range(15):
            if sid not in cases: continue
            if 'fail1' in cases[sid] and cases[sid]['fail1']:
                print("*** Strategy %d: Fail 1 ***" % sid)
                sorted_f1 = sorted(cases[sid]['fail1'], key=cases[sid]['fail1'].get, reverse=True)
                for c in sorted_f1[:10]:
                    print("%d\t%s" % (cases[sid]['fail1'][c], ip2str(c)))

            if 'fail2a' in cases[sid] and cases[sid]['fail2a']:
                print("*** Strategy %d: Fail 2a ***" % sid)
                sorted_f2a = sorted(cases[sid]['fail2a'], key=cases[sid]['fail2a'].get, reverse=True)
                for c in sorted_f2a[:10]:
                    print("%d\t%s" % (cases[sid]['fail2a'][c], ip2str(c)))

            if 'fail2b' in cases[sid] and cases[sid]['fail2b']:
                print("*** Strategy %d: Fail 2b ***" % sid)
                sorted_f2b = sorted(cases[sid]['fail2b'], key=cases[sid]['fail2b'].get, reverse=True)
                for c in sorted_f2b[:10]:
                    print("%d\t%s" % (cases[sid]['fail2b'][c], ip2str(c)))
            print("*** Strategy %d: Succ Rate ***" % sid)
            dip_list = []
            dip_list += cases[sid]['succ']
            dip_list += cases[sid]['fail1']
            dip_list += cases[sid]['fail2a']
            dip_list += cases[sid]['fail2b']
            dip_set = set(dip_list)
            for dip in dip_set:
                succ = cases[sid]['succ'].get(dip, 0)
                fail2a = cases[sid]['fail2a'].get(dip, 0)
                fail2b = cases[sid]['fail2b'].get(dip, 0)
                if succ + fail2a + fail2b != 0:
                    print("%s\t%f(%d/%d)" % (ip2str(dip), (succ/(succ+fail2a+fail2b)), succ, succ+fail2a+fail2b))



if __name__ == '__main__':
    p = Processor()
    print("-------------------------------------------------------")
    p.dump_stats()
    print("-------------------------------------------------------")
    p.dump_keywords()
    print("-------------------------------------------------------")
    p.dump_dns_poisoning()
    print("-------------------------------------------------------")
    p.dump_http_injection()
    print("-------------------------------------------------------")

