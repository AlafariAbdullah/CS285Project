from pydoc import plain
import socket
import secrets
import hmac, hashlib
from time import sleep
from commonSpace import takein, a, q
from Crypto.PublicKey import RSA
# =-=-=-=-=-=-=-=-=-= Set up a socket and connect as client =-=-=-=-=-=-=-=-=-=
client = socket.socket()
client.connect(('localhost', 6000))



# =-=-=-=-=-=-=-=-=-= Recieve RSA Public Key of Server =-=-=-=-=-=-=-=-=-=
public_rsa = RSA.import_key(takein(client)) # convert from bytes to key

# =-=-=-=-=-=-=-=-=-= Diffie-Hellman Setup =-=-=-=-=-=-=-=-=-=
# q and a are agreed on numbers
# q in a prime while and a  is a premitive root of q
q, a = q, a
Xb = secrets.randbelow(q) # random number bellow q
Yb = int(pow(a,Xb, q)) # calculate public key
# =-=-=-=-=-=-=-=-=-= Exchange Diffie-Hellman Public keys =-=-=-=-=-=-=-=-=-=
client.send(str(Yb).encode())
Ya = int(takein(client))
# =-=-=-=-=-=-=-=-=-= Diffie-Hellman Secret Key =-=-=-=-=-=-=-=-=-=
K = pow(Ya,Xb,q)
# print("Ya = ", Ya, "Yb = ", Yb)
print(K)
print("Diffie-Hellman key:", K)


# =-=-=-=-=-=-=-=-=-= Send Encoded Message =-=-=-=-=-=-=-=-=-=
plain_message = "Hello This is me Client"
cipherint = pow(int.from_bytes(plain_message.encode()),public_rsa.e, public_rsa.n) 
client.send(str(cipherint).encode())
print(plain_message)

# =-=-=-=-=-=-=-=-=-= Send Encoded Message With Ingegrity =-=-=-=-=-=-=-=-=-=
# Will use K from Diffle Hellman to sign the message
plain_message = "Hello This is me Client. Please check Integrity"
cipherint = pow(int.from_bytes(plain_message.encode()),public_rsa.e, public_rsa.n) 
cipher_byte = str(cipherint).encode()
# str(K).encode() to convert K to bytes
# 
signature = hmac.new(str(K).encode(), cipher_byte, hashlib.sha256).digest()
client.sendall(cipher_byte +b"\n"+ signature)

sleep(10)
# =-=-=-=-=-=-=-=-=-= Send Encoded Message With Ingegrity =-=-=-=-=-=-=-=-=-=
# Will use K from Diffle Hellman to sign the message
plain_message = "Hello This is me Client. Please check Integrity"
cipherint = pow(int.from_bytes(plain_message.encode()),public_rsa.e, public_rsa.n) 
cipher_byte = str(cipherint).encode()
# str(K).encode() to convert K to bytes
# 
signature = hmac.new(str(K).encode(), cipher_byte, hashlib.sha256).digest()
client.sendall(cipher_byte +b"\n"+ signature)
