# client 

#!/usr/bin/python

import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.bind(('localhost', 12345))
# time.sleep(2)
s.connect(('127.0.0.1', 54321))

s.send('1')
print s.recv(1024)
#sock.close()
