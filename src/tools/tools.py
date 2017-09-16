
from socket import ntohs, inet_ntoa, inet_aton
import struct


def cut(s, l):
    if len(s) > l:
        return s[:l] + "..."
    else:
        return s

def ip2str(i):
    return inet_ntoa(struct.pack('I', i))

def str2ip(s):
    return struct.unpack('I', inet_aton(s))[0]

def print_4tuple(s):
    parts = s.split('_')
    assert len(parts) == 4, "wrong format"
    sip, sport, dip, dport = [int(x) for x in s.split('_')]
    print("%s:%d -> %s:%d" % (ip2str(sip), ntohs(sport), ip2str(dip), ntohs(dport))) 

def parse_4tuple(s):
    parts = s.split('_')
    assert len(parts) == 4, "wrong format"
    sip, sport, dip, dport = [int(x) for x in s.split('_')]
    return ip2str(sip), ntohs(sport), ip2str(dip), ntohs(dport)

    
    

