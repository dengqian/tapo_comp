# server

#!/usr/bin/python
import socket, sys, time, struct

def make_ip(proto, srcip, ident=54321):  
    saddr = socket.inet_aton(srcip)
    daddr = socket.inet_aton(srcip)
    ihl_ver = (4 << 4) | 5
    return struct.pack('!BBHHHBBH4s4s',ihl_ver, 0, 0,
            ident, 0, 255, proto, 0, saddr, daddr)

def make_tcp(srcport, dstport, seq=123, ackseq=0, 
        urg=False, ack=True, psh=False, rst=False, syn=False, fin=False,
        window=18876):
    offset_res = (5 << 4) | 0
    flags = (fin | (syn << 1) | (rst << 2) | 
            (psh <<3) | (ack << 4) | (urg << 5))
    return struct.pack('!HHLLBBHHH', 
            srcport, dstport, seq, ackseq, offset_res,
            flags, window, 0, 0)

srcip = dstip = '127.0.0.1'
dst = (dstip, 0)
srcport, dstport = 54321, 12345 
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.bind((srcip, 54321))
s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.bind((srcip, 54321))


payload = '[RESPONSE]\n'
ip = make_ip(socket.IPPROTO_TCP, srcip)
syn_ack = make_tcp(srcport, dstport, 0, 1, 0, 1, 0, 0, 1, 0)

s1.listen(2)
ss, addr = s1.accept()
# print 'get connect from', addr

recv = s.recvfrom(65535)
print recv
s.sendto(ip+syn_ack, dst)

recv = s.recvfrom(65535)
recv = s.recvfrom(65535)
recv = s.recvfrom(65535)
recv = s.recvfrom(65535)
recv = s.recvfrom(65535)

# ack = make_tcp(srcport, dstport, 1, , 0, 1)
# s.sendto(ip+)



