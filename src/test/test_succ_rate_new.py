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

from Queue import Queue, Empty


THREAD_NUM = 100
JAIL_TIME = 95

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
    #pwget = subprocess.Popen("wget -4 -O /dev/null --tries=1 --timeout=5 --max-redirect 0 \"%s\"" % (url + KEYWORD), shell=True)
    #testing[website] = pwget
    #request = urllib2.Request("http://%s/?keyword=%s" % (ip, keyword),
    #                          headers = {'Host': domain, 'User-Agent': 'connectivity measurement'})

    ret = 0
    # Keep an eye on unexpected exceptions
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, 80))
        s.sendall("GET /?keyword=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: connectivity measurement\r\n\r\n" % (keyword, domain))
        data = s.recv(1024)
        s.shutdown(socket.SHUT_RDWR)
        s.close()
        if data:
            ret = 1
    except socket.timeout:
        # timeout
        ret = 0
        #print("Timeout.")
    except socket.error, serr:
        if serr[0] == errno.ECONNRESET:
            # reset
            ret = -1
            #print("Reset.")
        elif serr[0] == errno.ETIMEDOUT:
            # timeout
            ret = 0
            #print("Timeout.")
        else:
            ret = -99
            print("Socket error: %s" % serr)
    except Exception, err:
        ret = -99
        print("Exception: %s" % err)

    # sleep 2s to wait for late GFW rst
    time.sleep(2)
    #print("rst:attack1:*_%d" % ip2int(ip))
    type1rst = redis_conn.keys("rst:attack1:*_%d" % ip2int(ip))
    print(type1rst)
    #print("rst:attack2:*_%d" % ip2int(ip))
    type2rst = redis_conn.keys("rst:attack2:*_%d" % ip2int(ip))
    print(type2rst)
    if type1rst or type2rst:
        return -1
    else:
        if ret == -1:
            # server rst
            return 0
        elif ret == 0:
            return 0 # server no resp
        elif ret == 1:
            return 1 # success
        else:
            return -99 # unknown

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

    #ret = check_connectivity(domain, ip)
    ret = 1
    if ret == 1:
        # server alive and not in 90s
        # now we do the test
        print("Connectivity OK.")
        # reset counter
        down[domain] = 0
        ret = check_blockage(domain, ip)
        if ret == 1:
            # success
            return TEST_SUCCESS, 0
        elif ret == 0:
            # server no resp (assume it's because of our strategy)
            return TEST_SVR_NO_RESP, 0
        elif ret == -1:
            # failed because of gfw rst
            return TEST_GFW_RST, 0
        else:
            # other unknown reason
            return TEST_OTHER, 0
    else:
        down[domain] += 1
        # 5 failures in a row
        if down[domain] >= 5:
            print("%s(%s) is down." % (domain, ip))
        if ret == 0:
            # server no resp, we'll test later, we treat it the same as pre_gfw_rst
            return PRE_SVR_NO_RESP, 0
        elif ret == -1:
            # still in 90s, but we lose track perhaps due to rst packet loss
            return PRE_GFW_RST, 0
        else:
            # other unknown reason
            return PRE_OTHER, 0
        
def test_website_just_connectivity(domain, ip):
    print("Testing website %s(%s)..." % (domain, ip))

    ret = check_connectivity(domain, ip)
    if ret == 1:
        # server alive and not in 90s
        print("Connectivity OK.")
        return TEST_SUCCESS, 1
    elif ret == 0:
        # server no resp
        return TEST_SVR_NO_RESP, 1
    elif ret == -1:
        # failed because of svr rst, multiplex the TEST_GFW_RST
        return TEST_GFW_RST, 1
    else:
        # other unknown reason
        return TEST_OTHER, 1

def test_website_done(domain, ip, ret):
    global result, testing, jail_time
    ret, just_conn = ret
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
    jail_time[domain] = time.time()
    testing[domain] = False
    #update_display()
    update_statfile()

def worker_main(worker_id, just_conn):
    global q, result_lock, worker_done
    while not worker_done:
        try:
            domain, ip = q.get(True, 1)
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

def test_websites(sid, total_round_num, just_conn):
    global start_time, targets, result, testing, down, result_lock, q, worker_done
    start_time = time.strftime("%Y%m%d%H%M%S")
    p = start_tcpdump(sid)
    time.sleep(2)

    # Set initial jail time (spread the websites evenly during 90s)
    interval = float(JAIL_TIME-2) / len(targets)
    i = 0
    for domain, ip in targets:
        jail_time[domain] = time.time() - JAIL_TIME + 1 + interval * i
        i += 1

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

