#!/usr/bin/python

import pcap
import dpkt
import socket
import struct
import time

srcip = '10.24.0.109'
dstip = '10.21.2.192'
srcport = 54321
dstport = None

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s

def make_ip(proto, srcip, dstip, ident=54321):  
    saddr = socket.inet_aton(srcip)
    daddr = socket.inet_aton(dstip)
    ihl_ver = (4 << 4) | 5
    return struct.pack('!BBHHHBBH4s4s',ihl_ver, 0, 0,
            ident, 0, 255, proto, 0, saddr, daddr)

def make_tcp(srcport, dstport, options='', seq=0, ackseq=1, 
        urg=False, ack=True, psh=False, rst=False, syn=False, fin=False,
        window=14600):
    if(options != ''):
        leng = (len(options)+20) >> 2
        offset_res = (leng << 4) | 0
    else:
        offset_res = (5 << 4) | 0
    flags = (fin | (syn << 1) | (rst << 2) | 
            (psh <<3) | (ack << 4) | (urg << 5))
    check = 0
    urg_ptr = 0
    tcp_header = struct.pack('!HHLLBBHHH' , srcport, dstport, seq, ackseq,
            offset_res, flags,  window, check, urg_ptr)
    source_address = socket.inet_aton(srcip)
    dest_address = socket.inet_aton(dstip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(options) 
        
    psh = struct.pack('!4s4sBBH' , source_address , dest_address , 
            placeholder , protocol , tcp_length);
    psh = psh + tcp_header + options;
          
    tcp_check = checksum(psh)

    tcp_header = struct.pack('!HHLLBBH' , srcport, dstport, seq, ackseq,
            offset_res, flags, window) + struct.pack('H' , tcp_check) \
                    + struct.pack('H' , urg_ptr) + options
    return tcp_header

def make_options(mss=1460, sack_perm = 2):
    mss_kind = 2
    mss_len = 4
    nop = 1
    sack_perm_kind = 4
    options = struct.pack('!BBHBBBB', mss_kind, mss_len, mss, nop, nop, 
            sack_perm_kind, sack_perm)

    return options

def make_sack_option(length, left1, right1, left2=0, right2=0):
    nop = 1
    sack_kind = 5
    if (left2 == 0):
        sack = struct.pack('!BBBBLL', nop, nop, sack_kind, length, left1, right1)
    else:
        sack = struct.pack('!BBBBLLLL', nop, nop, sack_kind, length, left1, 
                right1, left2, right2)
    return sack

def make_ack(seq, ackseq):
    ack = make_tcp(srcport, dstport, options, seq, ackseq)
    return ack   

def make_sack(seq, ackseq, sack):
    sack = make_tcp(srcport, dstport, sack, seq, ackseq)
    return sack

class pkt_info:
    def __init__(self):
        self.flag = None
        self.seq = None
        self.ack = None
        self.leng = None
        self.src_port = None

def handle_packet(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return
    ip = eth.data
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return
    tcp = ip.data
    data = tcp.data
    src_port = tcp.sport
    dst_port = tcp.dport
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    if dst_port == 54321:
        p = pkt_info()
        p.src_port = src_port
        if tcp.flags & dpkt.tcp.TH_SYN:
            p.flag = 'Y';
        if tcp.flags & dpkt.tcp.TH_FIN:
            p.flag = 'F'
        if tcp.flags & dpkt.tcp.TH_RST:
            p.flag = 'R'
        p.seq = tcp.seq
        p.ack = tcp.ack
        p.leng = ip.len - ip.hl*4 - tcp.off*4
        return p

    return

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.bind((srcip, 54321))

ip = make_ip(socket.IPPROTO_TCP,srcip, dstip)

pkt_cnt = 0
seq_base = 0
last_seq = 0
last_ack = 0
retrans_state = 0
last_leng = 0
options = ''

cap = pcap.pcap()
for ts, pkt in cap:
    pi = handle_packet(pkt)
    if pi == None:  
        continue
    dstport = pi.src_port
    dst = ('10.21.2.192', dstport)

    if(pi.flag == 'Y'):
        syn_options = make_options()
        seq_base = pi.seq
        syn_ack = make_tcp(srcport, dstport, syn_options, seq_base, pi.seq+1, \
                0, 1, 0, 0, 1, 0)
        s.sendto(ip+syn_ack, dst)
        last_ack = pi.seq+1

    if(pi.leng > 0):
        pkt_cnt += 1
        seq_base = pi.ack
        if(retrans_state == 1):
            # send an new ack for the incoming pkt
            if(pi.seq == last_ack):
                ack = make_ack(seq_base, pi.seq+pi.leng)
                s.sendto(ip+ack, dst)
                last_ack = pi.seq + pi.leng
            else:
                # send an dup-ack 
                ack = make_ack(seq_base, last_ack)
                s.sendto(ip+ack, dst)

        elif(pi.seq < last_seq):
            ack = make_ack(seq_base, pi.seq+pi.leng)
            s.sendto(ip+ack, dst)
            last_ack = pi.seq + pi.leng
            retrans_state = 1
        else:
            if(pi.seq-seq_base < 14600):
                ack = make_ack(seq_base, pi.seq+pi.leng)
                s.sendto(ip+ack, dst)
                last_ack = pi.seq + pi.leng
            elif(pi.seq - seq_base < 20441):
                sack_block = make_sack_option(10, 14600+seq_base, 16060+seq_base)
                sack = make_sack(seq_base, last_ack, sack_block)
                s.sendto(ip+sack, dst)
        last_seq = pi.seq
        last_leng = pi.leng

    if(pi.flag == 'F'):
        rst = make_tcp(srcport, dstport, options, seq_base, pi.seq+1, 0, 0, 0, 1 )
        s.sendto(ip+rst, dst)
        print 'reseting'

