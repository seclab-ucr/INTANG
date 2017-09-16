#!/usr/bin/env python

import os
import sys
import subprocess
import time
import urllib2

from screen import *


MAX_PROC_NUM = 10
JAIL_TIME = 92

GOODWORD = 'goodword'
BADWORD = 'ultrasurf'


INNER_WEBSITES = {
    'kankan': 'http://search.kankan.com/',
    'sspai': 'http://sspai.com/',
    'zbj': 'http://search.zbj.com/',
    'xilu': 'http://www.xilu.com/jstj/20160421/',
    'ctrip': 'http://www.ctrip.com/',
    'meishichina': 'http://home.meishichina.com/search/',
    'wacai': 'http://bbs.wacai.com/',
    'xiachufang': 'http://www.xiachufang.com/',
    'boohee': 'http://www.boohee.com/',
    'iqiyi': 'http://so.iqiyi.com/so/',
    'guokr': 'http://www.guokr.com/',
    'qunar': 'http://www.qunar.com/',
    'dianping': 'http://s.dianping.com/topic/',
    '16fan': 'http://guide.16fan.com/',
    'tsinghua': 'http://career.tsinghua.edu.cn/docinfo/',
    'hexun': 'http://data.hexun.com/stock/spls/',
    'yinyuetai': 'http://so.yinyuetai.com/',
    'jumei': 'http://www.jumei.com/',
    'yeeyan': 'http://www.yeeyan.org/index/search/',
    'huaban': 'http://huaban.com/',
}

TARGETS = INNER_WEBSITES
KEYWORD = None

start_time = None

result = {}
jail_time = {}
target_domains = {}
target_ips = {}


def start_tcpdump(sid):
    print("Starting tcpdump...")
    p = subprocess.Popen(["tcpdump", "-i", "any", "-w", "./results/pktdump.pcap.%d.%s" % (sid, start_time), "tcp port 80"])
    return p

def stop_tcpdump(p):
    print("Stopping tcpdump...")
    os.system("kill %d" % p.pid)

def is_alldone(result, round_num):
    for website in TARGETS:
        if website not in result:
            return False
        if len(result[website]) < round_num:
            return False
    return True

def is_jailed(jail_time, website):
    if website not in jail_time:
        return False
    if time.time() - jail_time[website] > JAIL_TIME:
        del jail_time[website]
        return False
    return True

def update_screen():
    # clear the screen 
    clear_screen()

    print("Websites")
    for website in TARGETS:
        print("%20s " % (website))

def test_website(website):
    print("Testing website %s..." % website) 
    #pwget = subprocess.Popen("wget -4 -O /dev/null --tries=1 --timeout=5 --max-redirect 0 \"%s\"" % (url + KEYWORD), shell=True)
    #testing[website] = pwget
    request = urllib2.Request("http://%s/%s%s" % (target_ips[website], TARGETS[website][7:].split('/', 1)[1], KEYWORD),
                              headers = {'Host': target_domains[website]})
    try:
        obj = urllib2.urlopen(request, timeout=5)
        retcode = obj.getcode()
        return TEST_RESULT_SUCCEEDED
    except urllib2.HTTPError as herr:
        # 404
        if herr.code == 404:
            return TEST_RESULT_SUCCEEDED
    except urllib2.URLError as uerr:
        # timeout
        if isinstance(uerr.reason, socket.timeout):
            return TEST_RESULT_TIMEOUT
    except socket.error as serr:
        # reset
        return TEST_RES_RESET


def test_websites(sid, total_round_num):
    global start_time
    start_time = time.strftime("%Y%m%d%H%M%S")
    p = start_tcpdump(sid)
    time.sleep(2)
    testing = {}

    # init result
    for website in TARGETS:
        testing[website] = False
        result[website] = []

    # init subprocess pool
    from multiprocessing import Pool
    p = Pool(MAX_PROC_NUM)

    while not is_alldone(result, total_round_num):
        # pick the least tested website
        min_website = None
        min_count = 999999
        for website in TARGETS:
            # skip websites if being tested or in jail
            if testing[website]:
                continue
            if is_jailed(website):
                continue
            if len(result[website]) < min_count:
                min_website = website
                min_count = len(result[website])
        if min_count >= total_round_num:
            time.sleep(0.5)
            continue
        
        #if is_jailed(website):
        #    # in jail, skip
        #    print("%s in jail. %ds left. skip..." % (website, jail_time[website] + JAIL_TIME - time.time()))

        testing[website] = True
        res = p.apply_async(test_website, (min_website,))


        for website, url in TARGETS.iteritems():

            while len(testing) >= MAX_PROC_NUM:
                # clean working set
                websites = testing.keys()
                for website in websites:
                    ret = testing[website].poll()
                    if ret is not None:
                        if ret == 4:
                            # connect reset by peer (reset by GFW?)
                            jail_time[website] = time.time()
                        del testing[website]
                time.sleep(0.5)

            else:
                if testing.get(website):
                    # testing, skip
                    ret = testing[website].poll()
                    if ret is not None:
                        if ret == 4:
                            # connect reset by peer (reset by GFW?)
                            jail_time[website] = time.time()
                        del testing[website]
                else:

            time.sleep(0.1)

    print("All tests done.")

    time.sleep(5)
    stop_tcpdump(p)
    os.system("./stop.sh")
    time.sleep(0.5)
    os.system("cp /var/log/intangd.log ./results/intangd.log.%d.%s" % (sid, start_time))
    os.system("cp /usr/local/share/intangd/dump.rdb ./results/dump.rdb.%d.%s" % (sid, start_time))
    os.system("cd results && tar zcf result.%d.%s.tar.gz pktdump.pcap.%d.%s intangd.log.%d.%s dump.rdb.%d.%s" % (sid, start_time, sid, start_time, sid, start_time, sid, start_time))


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Needs root privilege.")
        sys.exit(0)
    import os.path
    if not os.path.isfile("intangd"):
        print("Cannot find intangd. Please try \"make\".")
        sys.exit(0)
        
    if len(sys.argv) != 3:
        print("Usage: %s <sid> <num of rounds>" % sys.argv[0])
    sid = int(sys.argv[1])
    rounds = int(sys.argv[2])
    if sid == 0:
        KEYWORD = GOODWORD
    else:
        KEYWORD = BADWORD
    # resolve target domain name to IP
    for website, url in TARGETS.iteritems():
        if not url.startswith("http://"):
            print("URL must start with 'http://'. %s" % url)
            sys.exit(-1)
        domain = url[7:].split('/', 1)[0]
        ip = socket.gethostbyname(website)
        target_domains[website] = domain
        target_ips[website] = ip
    print(target_ips)
    os.system("mkdir results")
    os.system("chmod 777 results")
    print("Stopping intang and deleting redis db.")
    os.system("./stop.sh")
    time.sleep(1)
    os.system("rm /usr/local/share/intangd/dump.rdb")
    print("Restarting intang.")
    os.system("./run.sh %d" % sid)
    time.sleep(1)
    test_websites(sid, rounds)

