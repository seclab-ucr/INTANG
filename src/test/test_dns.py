#!/usr/bin/env python


import redis
import socket
import struct
import subprocess
import time


TEST_ROUNDS = 50

JAIL_TIME = 95

TEST_SUCCESS = 1
TEST_FAILED = 2
TEST_SVR_NO_RESP = 3
TEST_OTHER = 4

resolvers = [
    '216.146.35.35',
    '216.146.36.36',
    '208.67.222.222',
    '208.67.220.220',
]

jail_time = {}

# connect to redis
redis_conn = redis.StrictRedis(host='localhost', port=6389, db=0)

results = {
}
for resolver_ip in resolvers:
    results[resolver_ip] = []

def ip2int(addr):                                                               
    return struct.unpack("I", socket.inet_aton(addr))[0]                       

def is_all_done():
    for resolver_ip in resolvers:
        if len(results[resolver_ip]) < TEST_ROUNDS:
            return False
    return True

def is_in_jail(resolver_ip):
    if resolver_ip in jail_time:
        if jail_time[resolver_ip] + JAIL_TIME < time.time():
            del jail_time[resolver_ip]
            return False
        else:
            return True
    return False

def update_statfile():
    f = open('status.log', 'w')

    for resolver_ip in resolvers:
        f.write("%30s : " % (resolver_ip))
        for res in results[resolver_ip]:
            if res == TEST_SUCCESS:
                # success
                f.write('+')
            elif res == TEST_SVR_NO_RESP:
                # svr no resp
                f.write('*')
            elif res == TEST_FAILED:
                # reset (may differentiate type-1 and type-2 later)
                f.write('-')
            else:
                # unknown
                f.write('?')
        f.write("\n")
    f.close()

while not is_all_done():
    for resolver_ip in resolvers:
        if is_in_jail(resolver_ip):
            time.sleep(0.1)
            continue

        ret = subprocess.check_output("dig +tcp @%s www.dropbox.com" % resolver_ip, shell=True)
        #print(ret)
        # sleep 2s to wait for late GFW rst
        time.sleep(2)
        #print("rst:attack1:*_%d" % ip2int(ip))
        type1rst = redis_conn.keys("rst:attack1:*_%d" % ip2int(resolver_ip))
        print(type1rst)
        #print("rst:attack2:*_%d" % ip2int(ip))
        type2rst = redis_conn.keys("rst:attack2:*_%d" % ip2int(resolver_ip))
        print(type2rst)
        if type1rst or type2rst:
            results[resolver_ip].append(TEST_FAILED)
            jail_time[resolver_ip] = time.time()
        elif "connection reset" in ret:
            pass
        else:
            results[resolver_ip].append(TEST_SUCCESS)
            
        update_statfile()
        time.sleep(0.1)


for resolver_ip in resolvers:
    print("%s, %d, %d" % (resolver_ip, results[resolver_ip].count(TEST_SUCCESS), results[resolver_ip].count(TEST_FAILED)))

