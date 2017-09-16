#!/usr/bin/env python

import os
import sys
import socket
import errno
import time
import redis
import struct


RET_SUCCESS = 1
RET_SVR_NO_RESP = 2
RET_GFW_RST = 3
RET_OTHER = 99

#HTTP_REQ_FORMAT = "GET /?keyword=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: connectivity measurement\r\n\r\n"


def ip2int(addr):                                                               
    return struct.unpack("I", socket.inet_aton(addr))[0]                       

def probe_http_server(domain, ip, keyword):
    redis_conn = redis.StrictRedis(host='localhost', port=6389, db=0)

    print("Sending request to %s(%s) with keyword '%s'..." % (domain, ip, keyword)) 

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
        if data and len(data) > 1:
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
        return RET_GFW_RST
    else:
        if ret == -1:
            # server rst
            return RET_SVR_NO_RESP
        elif ret == 0:
            return RET_SVR_NO_RESP # server no resp
        elif ret == 1:
            return RET_SUCCESS # success
        else:
            return RET_OTHER # unknown



def test_normal():
    ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword")
    #ret = probe_http_server("www.baidu.com", "103.235.46.39", "ultrasurf")
    print(ret)

def test_gfw_rst():
    #ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword")
    ret = probe_http_server("sspai.com", "119.23.141.248", "ultrasurf")
    print(ret)

def test_no_resp():
    ret = probe_http_server("www.baidu.com", "3.235.46.39", "goodword")
    #ret = probe_http_server("www.baidu.com", "103.235.46.39", "ultrasurf")
    print(ret)

def test_port_reuse():
    ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword")
    print(ret)
    ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword")
    print(ret)


if __name__ == "__main__":
    domain = sys.argv[1]
    ip = sys.argv[2]
    ret = probe_http_server(domain, ip, "goodword")
    print(ret)
    ret = probe_http_server(domain, ip, "ultrasurf")
    print(ret)
    #test_normal()
    #test_port_reuse()
    #test_gfw_rst()
    #test_no_resp()


