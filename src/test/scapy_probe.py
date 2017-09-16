#!/usr/bin/env python

import os
import random
import sys

from scapy.all import IP, TCP, Raw, sr, send, fragment

RET_SUCCESS = 1
RET_SYN_NO_RESP = 2
RET_REQ_NO_RESP = 3
RET_GFW_RST = 4
RET_OTHER = 99

TIMEOUT_WAIT_SYN_ACK = 1
TIMEOUT_WAIT_HTTP_RESP = 3

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

HTTP_REQ_FORMAT = "GET /?keyword=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: connectivity measurement\r\n\r\n"


def disable_outgoing_rst():
    os.system("iptables -A OUTPUT -p tcp --dport 80 --tcp-flags RST,ACK RST -m ttl ! --ttl-eq 163 -j DROP")

def enable_outgoing_rst():
    os.system("iptables -D OUTPUT -p tcp --dport 80 --tcp-flags RST,ACK RST -m ttl ! --ttl-eq 163 -j DROP")


def probe_http_server(domain, ip, keyword, sport=0):

    if sport == 0:
        sport = random.randint(1025, 65535)
    ISN = random.getrandbits(32)
    window = 1460

    synack_cnt = 0
    synack_multi_seq = False
    synack_seq = 0
    try_num = 0
    synack_ttl = 0
    while try_num < 4:
        try_num += 1
        syn = IP(dst=ip)/TCP(sport=sport, dport=80, flags='S', seq=ISN, options=[('MSS', 1460)])
        ans, una = sr(syn, multi=True, timeout=TIMEOUT_WAIT_SYN_ACK, verbose=0)

        for _, pkt in ans:
            if TCP in pkt:
                if pkt[TCP].flags == SYN | ACK:
                    if pkt[TCP].ack == ISN+1:
                        synack_cnt += 1
                        if synack_seq != 0 and pkt[TCP].seq != synack_seq:
                            synack_multi_seq = True
                        synack_seq = pkt[TCP].seq
                        synack_ttl = pkt[IP].ttl
                    #pkt.show()
                if pkt[TCP].flags == ACK:
                    # a connection already exists, change a port
                    sport = random.randint(1025, 65535)

        if synack_cnt > 0:
            break

    if synack_cnt == 0:
        return RET_SYN_NO_RESP
    if synack_cnt > 1 and synack_multi_seq:
        # received multiple SYN/ACK with different seq num. could be in 90s blocking period
        return RET_GFW_RST
    
    ack = IP(dst=ip)/TCP(sport=sport, dport=80, flags='A', seq=ISN+1, ack=synack_seq+1, options=[('MSS', 1460)])
    send(ack, verbose=0)

    httpresp_cnt = 0
    gfwrst_cnt = 0
    ret = 0
    try_num = 0
    while try_num < 3:
        try_num += 1
        reqstr = HTTP_REQ_FORMAT % (keyword, domain)
        httpreq = IP(dst=ip)/TCP(sport=sport, dport=80, flags='A', seq=ISN+1, ack=synack_seq+1, window=window)/Raw(load=reqstr)
        #httpreq = fragment(httpreq, 40)
        ans, una = sr(httpreq, multi=True, timeout=TIMEOUT_WAIT_HTTP_RESP, verbose=0)

        for _, pkt in ans:
            if TCP in pkt:
                if pkt[TCP].flags | ACK and pkt[TCP].payload:
                    resp_line = pkt[TCP].payload.load.split('\n', 1)[0]
                    #print(resp_line)
                    parts = resp_line.split()
                    if parts[0] == 'HTTP/1.1' or parts[0] == 'HTTP/1.0':
                        httpresp_cnt += 1
                        if parts[1] == '200' and parts[2] == 'OK':
                            pass
                if pkt[TCP].flags == RST | ACK:
                    # from server or from GFW?
                    # very likely from GFW
                    gfwrst_cnt += 1
                if pkt[TCP].flags == RST:
                    # from server or from GFW?
                    # likely, but not definitely, to be conservative
                    if pkt[IP].ttl < synack_ttl - 1 or pkt[IP].ttl > synack_ttl + 1:# or pkt[IP].flags == 0:
                        gfwrst_cnt += 1
        
        if httpresp_cnt > 0 or gfwrst_cnt > 0:
            break

    # terminate the connection
    rst = IP(dst=ip, ttl=163)/TCP(sport=sport, dport=80, flags='R', seq=ISN+1+len(reqstr), window=0)
    send([rst, rst, rst], verbose=0)

    if gfwrst_cnt > 0:
        return RET_GFW_RST
    if httpresp_cnt > 0:
        return RET_SUCCESS
    if httpresp_cnt == 0:
        return RET_REQ_NO_RESP

    # will never reach here
    return RET_OTHER


def test_normal():
    disable_outgoing_rst()
    ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword")
    #ret = probe_http_server("www.baidu.com", "103.235.46.39", "ultrasurf")
    print(ret)
    enable_outgoing_rst()

def test_gfw_rst():
    disable_outgoing_rst()
    #ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword")
    ret = probe_http_server("sspai.com", "119.23.141.248", "ultrasurf")
    print(ret)
    enable_outgoing_rst()

def test_no_resp():
    disable_outgoing_rst()
    ret = probe_http_server("www.baidu.com", "3.235.46.39", "goodword")
    #ret = probe_http_server("www.baidu.com", "103.235.46.39", "ultrasurf")
    print(ret)
    enable_outgoing_rst()

def test_port_reuse():
    disable_outgoing_rst()
    ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword", 1234)
    print(ret)
    ret = probe_http_server("www.baidu.com", "103.235.46.39", "goodword", 1234)
    print(ret)
    enable_outgoing_rst()


if __name__ == "__main__":
    domain = sys.argv[1]
    ip = sys.argv[2]
    disable_outgoing_rst()
    ret = probe_http_server(domain, ip, "goodword")
    print(ret)
    enable_outgoing_rst()
    #test_normal()
    #test_port_reuse()
    #test_gfw_rst()
    #test_no_resp()


