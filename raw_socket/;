#!/usr/bin/python
import socket, sys, time, struct
import time

def make_ip(proto, srcip, ident=54321):  
    saddr = socket.inet_aton(srcip)
    daddr = socket.inet_aton(srcip)
    ihl_ver = (4 << 4) | 5
    return struct.pack('!BBHHHBBH4s4s',ihl_ver, 0, 0,
            ident, 0, 255, proto, 0, saddr, daddr)

def make_tcp(srcport, dstport, seq=123, ackseq=0, 
        urg=False, ack=False, psh=False, rst=False, syn=False, fin=False,
        window=5840):
    offset_res = (5 << 4) | 0
    flags = (fin | (syn << 1) | (rst << 2) | 
            (psh <<3) | (ack << 4) | (urg << 5))
    return struct.pack('!HHLLBBHHH', 
            srcport, dstport, seq, ackseq, offset_res,
            flags, window, 0, 0)

srcip = dstip = '127.0.0.1'
dst = (dstip,  54321)
srcport, dstport = 12345, 54321
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.bind((srcip, 12345))

ip = make_ip(socket.IPPROTO_TCP, srcip)
payload = 'SENDING  MESSAGE  TEST'

syn = make_tcp(srcport, dstport, 0, 0, 0, 0, 0, 0, 1)
s.sendto(ip+syn, dst)

response, addr = s.recvfrom(65535)

ack = make_tcp(srcport, dstport, 1, 1, 0, 1)
s.sendto(ip+ack, dst)

header = ''' POST  HTTP/1.1\r'''

data = make_tcp(srcport, dstport, 1, 1, 0, 1, 1)
s.sendto(ip+data+header+payload+'1\n', dst)
data = make_tcp(srcport, dstport, 41, 1, 0, 1, 1)
s.sendto(ip+data+header+payload+'2\n', dst)
data = make_tcp(srcport, dstport, 81, 1, 0, 1, 1)
s.sendto(ip+data+header+payload+'3\n', dst)

time.sleep(0.5)

data = make_tcp(srcport, dstport, 41, 1, 0, 1, 1)
s.sendto(ip+data+header+payload+'1\n', dst)

