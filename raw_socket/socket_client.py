import socket  
  
address = ('127.0.0.1', 31500)  
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.connect(address)  
    
data = s.recv(512)  

print 'the data received is',data  
 
s.send('hihi')  
   
s.close()  
