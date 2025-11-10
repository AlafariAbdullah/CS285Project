# q and a are agreed on numbers
# q in a prime while and a  is a premitive root of q
q = 7
a = 5

import socket
#to make recieving data easier in each class
def takein(connection : socket.socket):
    
    try:
        while True:
            data = connection.recv(1024)
            if not data:
                break
            return (data) 
    finally:
        pass
