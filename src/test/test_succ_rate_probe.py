#!/usr/bin/env python

import errno
import os
import random
import redis
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib2

from Queue import Queue, Empty

import probe

THREAD_NUM = 100
JAIL_TIME = 92

GOODWORD = 'goodword'
BADWORD = 'ultrasurf'
#BADWORD = 'goodword'


KEYWORD = None

start_time = None

q = Queue()
targets = []
result = {}
testing = {}
jail_time = {}
down = {}
redis_conn = None
worker_done = False
result_lock = None

PRE_SVR_NO_RESP = 1
PRE_GFW_RST = 2
PRE_OTHER = 3
TEST_SUCCESS = 4
TEST_SVR_NO_RESP = 5
TEST_GFW_RST = 6
TEST_OTHER = 7
TESTING = 99

def retstr(retcode):
    s = {
        1: "PRE_SVR_NO_RESP",
        2: "PRE_GFW_RST",
        3: "PRE_OTHER",
        4: "TEST_SUCCESS",
        5: "TEST_SVR_NO_RESP",
        6: "TEST_GFW_RST",
        7: "TEST_OTHER",
        99: "TESTING",
    }
    return s[retcode]

def ip2int(addr):                                                               
    return struct.unpack("I", socket.inet_aton(addr))[0]                       

def read_target_websites(target_file):
    global targets
    f = open(target_file, 'r')
    for line in f:
        line = line[:-1]
        parts = line.split(',')
        domain = parts[1]
        ip = parts[2]
        targets.append((domain, ip))
    f.close()

def select_the_least_tested_website(total_rounds):
    global targets, result, testing, down
    min_target = None
    min_count = 999999
    while True:
        for domain, ip in targets:
            # skip websites if being tested or in jail
            if testing[domain]:
                continue
            if down[domain] >= 5:
                continue
            if in_jail(domain):
                continue
            if len(result[domain]) >= total_rounds:
                continue
            if len(result[domain]) < min_count:
                min_target = domain, ip
                min_count = len(result[domain])
        if min_target:
            break
        time.sleep(1)
    return min_target

def _send_request(domain, ip, keyword):
    print("Sending request to %s(%s) with keyword '%s'..." % (domain, ip, keyword)) 
    return probe.probe_http_server(domain, ip, keyword)

def check_connectivity(domain, ip):
    print("Checking connectivity %s..." % domain) 
    return _send_request(domain, ip, GOODWORD)

def check_blockage(domain, ip):
    print("Testing %s..." % domain) 
    return _send_request(domain, ip, BADWORD)

def start_tcpdump(sid):
    print("Starting tcpdump...")
    p = subprocess.Popen(["tcpdump", "-i", "any", "-w", "./results/pktdump.pcap.%d.%s" % (sid, start_time), "tcp port 80"])
    return p

def stop_tcpdump(p):
    print("Stopping tcpdump...")
    os.system("kill %d" % p.pid)

def is_alldone(total_rounds):
    global targets, result
    for domain, ip in targets:
        if domain not in result:
            #print("%s not in result" % domain)
            return False
        if down[domain]:
            continue
        if len(result[domain]) < total_rounds:
            #print("%s not finished. %s" % (domain, len(result[domain])))
            return False
    return True

def in_jail(website):
    global jail_time
    if website not in jail_time:
        return False
    if time.time() - jail_time[website] > JAIL_TIME:
        del jail_time[website]
        return False
    return True

def update_display():
    global targets, result
    # clear the screen 
    print "\033[2J"
    print "\033[1;1H"

    for domain, ip in targets:
        print "%30s : " % (domain), 
        for res in result[domain]:
            if res == TEST_SUCCESS:
                # success
                print '+',
            elif res == TEST_SVR_NO_RESP:
                # svr no resp
                print '*',
            elif res == TEST_GFW_RST:
                # reset (may differentiate type-1 and type-2 later)
                print '-',
            elif res == TESTING:
                # testing
                print '>',
            else:
                # unknown
                print '?',
        print ""

def update_statfile():
    global targets, result
    # clear the screen 
    f = open('status.log', 'w')

    for domain, ip in targets:
        f.write("%30s : " % (domain))
        for res in result[domain]:
            if res == TEST_SUCCESS:
                # success
                f.write('+')
            elif res == TEST_SVR_NO_RESP:
                # svr no resp
                f.write('*')
            elif res == TEST_GFW_RST:
                # reset (may differentiate type-1 and type-2 later)
                f.write('-')
            elif res == TESTING:
                # testing
                f.write('>')
            else:
                # unknown
                f.write('?')
        f.write("\n")
    f.close()

def test_website(domain, ip):
    print("Testing website %s(%s)..." % (domain, ip))

    ret = check_connectivity(domain, ip)
    if ret == probe.RET_SUCCESS:
        # server alive and not in 90s
        # now we do the test
        print("Connectivity OK.")
        # reset counter
        down[domain] = 0
        ret = check_blockage(domain, ip)
        if ret == probe.RET_SUCCESS:
            # success
            return TEST_SUCCESS
        elif ret == probe.RET_SYN_NO_RESP or ret == probe.RET_REQ_NO_RESP:
            # server no resp (assume it's because of our strategy)
            return TEST_SVR_NO_RESP
        elif ret == probe.RET_GFW_RST:
            # failed because of gfw rst
            return TEST_GFW_RST
        else:
            # other unknown reason
            return TEST_OTHER
    else:
        down[domain] += 1
        # 5 failures in a row
        if down[domain] >= 5:
            print("%s(%s) is down." % (domain, ip))
        if ret == probe.RET_SYN_NO_RESP or ret == probe.RET_REQ_NO_RESP:
            # server no resp, we'll test later, we treat it the same as pre_gfw_rst
            return PRE_SVR_NO_RESP
        elif ret == probe.RET_GFW_RST:
            # still in 90s, but we lose track perhaps due to rst packet loss
            return PRE_GFW_RST
        else:
            # other unknown reason
            return PRE_OTHER
        
def test_website_just_connectivity(domain, ip):
    print("Testing website %s(%s)..." % (domain, ip))

    ret = check_connectivity(domain, ip)
    if ret == probe.RET_SUCCESS:
        # server alive and not in 90s
        print("Connectivity OK.")
        return TEST_SUCCESS
    elif ret == probe.RET_SYN_NO_RESP or ret == probe.RET_REQ_NO_RESP:
        # server no resp
        return TEST_SVR_NO_RESP
    elif ret == probe.RET_GFW_RST:
        # failed because of svr rst, multiplex the TEST_GFW_RST
        return TEST_GFW_RST
    else:
        # other unknown reason
        return TEST_OTHER

def test_website_done(domain, ip, ret):
    global result, testing, jail_time
    print("Testing website %s(%s) done. Ret: %s" % (domain, ip, retstr(ret)))
    if ret in (PRE_SVR_NO_RESP, PRE_GFW_RST, PRE_OTHER):
        # failed in pre-test stage, we just discard the result
        result[domain] = result[domain][:-1]
        if ret == PRE_GFW_RST or ret == PRE_SVR_NO_RESP:
            jail_time[domain] = time.time()
    else:
        if ret == TEST_GFW_RST:
            jail_time[domain] = time.time()
        # update the result
        result[domain][-1] = ret
    testing[domain] = False
    #update_display()
    update_statfile()

def worker_main(worker_id, just_conn):
    global q, result_lock, worker_done
    while not worker_done:
        try:
            print("q.get. qsize: %d" % q.qsize())
            domain, ip = q.get(True, 1)
            print("after q.get. qsize: %d" % q.qsize())
            sys.stdout.flush()
            if just_conn == 1:
                ret = test_website_just_connectivity(domain, ip)
            else:
                ret = test_website(domain, ip)
            result_lock.acquire()
            test_website_done(domain, ip, ret)
            result_lock.release()
            q.task_done()
        except Empty:
            time.sleep(0.2)
    print("Worker %d done." % worker_id)
    sys.stdout.flush()

def test_websites(sid, total_round_num, just_conn):
    global start_time, targets, result, testing, down, result_lock, q, worker_done
    start_time = time.strftime("%Y%m%d%H%M%S")
    p = start_tcpdump(sid)
    time.sleep(2)

    # init result
    for domain, ip in targets:
        testing[domain] = False
        result[domain] = []
        down[domain] = 0

    threads = []
    for i in range(THREAD_NUM):
        t = threading.Thread(target=worker_main, args=(i+1, just_conn,))
        t.start()
        threads.append(t)

    result_lock = threading.Lock()
    worker_done = False

    probe.disable_outgoing_rst()

    while not is_alldone(total_round_num):
        # pick the least tested website
        domain, ip = select_the_least_tested_website(total_round_num)
        
        result_lock.acquire()
        testing[domain] = True
        result[domain].append(TESTING)
        result_lock.release()

        q.put((domain, ip))

        time.sleep(0.1)

    q.join()
    worker_done = True
    for i in range(THREAD_NUM):
        threads[i].join()

    probe.enable_outgoing_rst()

    print("All tests done.")

    time.sleep(5)
    stop_tcpdump(p)
    os.system("./stop.sh")
    time.sleep(0.5)
    os.system("cp /var/log/intangd.log ./results/intangd.log.%d.%s" % (sid, start_time))
    os.system("cp /usr/local/share/intangd/dump.rdb ./results/dump.rdb.%d.%s" % (sid, start_time))
    os.system("cp status.log ./results/status.log.%d.%s" % (sid, start_time))
    os.system("cp output.log ./results/output.log.%d.%s" % (sid, start_time))
    os.system("cd results && tar zcf result.%d.%s.tar.gz pktdump.pcap.%d.%s intangd.log.%d.%s dump.rdb.%d.%s status.log.%d.%s output.log.%d.%s" % (sid, start_time, sid, start_time, sid, start_time, sid, start_time, sid, start_time, sid, start_time))


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Needs root privilege.")
        sys.exit(0)
    import os.path
    if not os.path.isfile("intangd"):
        print("Cannot find intangd. Please try \"make\".")
        sys.exit(0)
        
    if len(sys.argv) != 5:
        print("Usage: %s <target file> <sid> <num of rounds> <just connectivity>" % sys.argv[0])
        sys.exit(0)
    target_file = sys.argv[1]
    sid = int(sys.argv[2])
    rounds = int(sys.argv[3])
    just_conn = int(sys.argv[4])
    if sid == 0:
        KEYWORD = GOODWORD
    else:
        KEYWORD = BADWORD
    read_target_websites(target_file)

    os.system("mkdir results")
    os.system("chmod 777 results")
    print("Stopping intang and deleting redis db.")
    os.system("./stop.sh")
    time.sleep(1)
    os.system("rm /usr/local/share/intangd/dump.rdb")
    print("Restarting intang.")
    os.system("./run.sh %d" % sid)
    time.sleep(1)

    # connect to redis
    redis_conn = redis.StrictRedis(host='localhost', port=6389, db=0)

    test_websites(sid, rounds, just_conn)

