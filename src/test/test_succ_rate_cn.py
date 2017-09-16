#!/usr/bin/env python

import os
import sys
import subprocess
import time


MAX_PROC_NUM = 20
JAIL_TIME = 92

GOODWORD = 'goodword'
BADWORD = 'ultrasurf'


OUTTER_WEBSITES = {
    'yahoo.com': 'http://www.yahoo.com/',
    'wikipedia.org': 'http://www.wikipedia.org/',
    'amazon.com': 'http://www.amazon.com/',
    'live.com': 'http://www.live.com/',
    'vk.com': 'http://www.vk.com/',
    'linkedin.com': 'http://www.linkedin.com/',
    'yandex.ru': 'http://www.yandex.ru/',
    'reddit.com': 'http://www.reddit.com/',
    'ebay.com': 'http://www.ebay.com/',
    'msn.com': 'http://www.msn.com/',
    'stackoverflow.com': 'http://www.stackoverflow.com/',
    'microsoft.com': 'http://www.microsoft.com/',
    'mail.ru': 'http://www.mail.ru/',
    'netflix.com': 'http://www.netflix.com/',
    'paypal.com': 'http://www.paypal.com/',
    'ok.ru': 'http://www.ok.ru/',
    'imgur.com': 'http://www.imgur.com/',
    'github.com': 'http://www.github.com/',
    'imdb.com': 'http://www.imdb.com/',
    'whatsapp.com': 'http://www.whatsapp.com/',
    'office.com': 'http://www.office.com/',
    'adobe.com': 'http://www.adobe.com/',
    'craigslist': 'http://www.craigslist.org/',
    'twitch.tv': 'http://www.twitch.tv/',
    'quora.com': 'http://www.quora.com/',
    'cnn.com': 'http://www.cnn.com/',
    'rakuten.jp': 'http://search.rakuten.co.jp/',
    'coccoc.com': 'http://coccoc.com/',
    'ask.com': 'http://www.ask.com/',
    'bbc.com': 'http://www.bbc.com/',
    'salesforce.com': 'http://www.salesforce.com/',
    'outbrain.com': 'http://www.outbrain.com/',
    'booking.com': 'http://www.booking.com/',
    'indiatimes.com': 'http://www.indiatimes.com/',
    'diply.com': 'http://www.diply.com/',
    'globo.com': 'http://www.globo.com/',
    'uol.com.br': 'http://www.uol.com.br/',
    'dailymail.co.uk': 'http://www.dailymail.co.uk/',
    'ettoday.net': 'http://www.ettoday.net/',
    'daum.net': 'http://www.daum.net/',
    'indeed.com': 'http://www.indeed.com/',
    'blastingnews.com': 'http://www.blastingnews.com/',
    'savefrom.net': 'http://en.savefrom.net/',
    'trello.com': 'http://trello.com/',
    'uptodown.com': 'http://en.uptodown.com/',
    'deviantart.com': 'http://www.deviantart.com/',
    'tribunnews.com': 'http://www.tribunnews.com/',
    'addthis.com': 'http://www.addthis.com/',
    'theguardian.com': 'http://www.theguardian.com/',
    'cnet.com': 'http://www.cnet.com/',

#    'hulu.com': 'http://www.hulu.com/',
#    'royalmail.com': 'http://www.royalmail.com/',
#    'nationwide.co.uk': 'http://www.nationwide.co.uk/',
#    'currys.co.uk': 'http://www.currys.co.uk/',
#    'livedoor.com': 'http://search.livedoor.com/',
#    'naver.jp': 'http://matome.naver.jp/',
#    'nonews.com': 'http://legacy.nownews.com/',
#    'cheers.com.tw': 'http://www.cheers.com.tw/',
#    'u-car.com.tw': 'http://www.u-car.com.tw/',
#    'gaana.com': 'http://gaana.com/',
#    'monster.com': 'http://www.monsterindia.com/',
#    'rambler.ru': 'http://nova.rambler.ru/',
#    'eldorado.ru': 'http://www.eldorado.ru/',
#    'shaw.ca': 'http://www.shaw.ca/',
#    'cic.gc.ca': 'http://www.cic.gc.ca/',
#    'sbs.com.au': 'http://www.sbs.com.au/',
#    'nla.gov.au': 'http://www.nla.gov.au/',
}


TARGETS = OUTTER_WEBSITES
KEYWORD = None

start_time = None


def start_tcpdump(sid):
    print("Starting tcpdump...")
    p = subprocess.Popen(["tcpdump", "-i", "any", "-w", "./results/pktdump.pcap.%d.%s" % (sid, start_time), "tcp port 80"])
    return p

def stop_tcpdump(p):
    print("Stopping tcpdump...")
    os.system("kill %d" % p.pid)

def is_alldone(test_count, round_num):
    for website in TARGETS:
        if website not in test_count:
            return False
        if test_count[website] < round_num:
            return False
    return True

def is_jailed(jail_time, website):
    if website not in jail_time:
        return False
    if time.time() - jail_time[website] > JAIL_TIME:
        del jail_time[website]
        return False
    return True

def test_websites(sid, rounds):
    global start_time
    start_time = time.strftime("%Y%m%d%H%M%S")
    p = start_tcpdump(sid)
    time.sleep(2)
    jail_time = {}
    testing = {}
    test_count = {}

    i = 0
    while not is_alldone(test_count, rounds):
        print("[Round %d]" % (i+1))
        for website, url in TARGETS.iteritems():
            if website not in test_count:
                test_count[website] = 0

            if test_count[website] >= rounds:
                # the website has been done
                continue

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

            if is_jailed(jail_time, website):
                # in jail, skip
                print("%s in jail. %ds left. skip..." % (website, jail_time[website] + JAIL_TIME - time.time()))
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
                    print("Testing website %s..." % website) 
                    pwget = subprocess.Popen("wget -4 -O /dev/null --tries=1 --timeout=5 --max-redirect 0 \"%s\"" % (url + KEYWORD), shell=True)
                    testing[website] = pwget
                    test_count[website] += 1

            time.sleep(0.1)
        i += 1

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

