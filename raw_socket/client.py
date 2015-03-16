# client 

#!/usr/bin/python

import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# time.sleep(2)
s.connect(('10.24.0.109', 54321))

f = open('test1.py')

header = ''' POST  HTTP/1.1\r'''
s.send(header + str(f.readlines()))
s.close()
