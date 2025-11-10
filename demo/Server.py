import socket
import secrets
# Set up q and a for DH key generation
from commonSpace import takein, a , q
from Crypto.PublicKey import RSA
import hashlib, hmac
    
        
        
# =-=-=-=-=-=-=-=-=-= Generate RSA key Pair =-=-=-=-=-=-=-=-=-=
key = RSA.generate(bits=1024)
private_rsa, public_rsa = key.export_key(), key.public_key().export_key()


# =-=-=-=-=-=-=-=-=-= Set up a socket and connection =-=-=-=-=-=-=-=-=-=
# socket.socket(socket_family, socket_type) -> AF_INET - IPv4, SOCK_STREAM - TCP
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# socket.bind((IP_Address, PORT)) - Tuple not 1 Argument - binds socket to address
serverSocket.bind(('localhost', 6000))
# socket.listen(number of connections to wait before calling accept)
serverSocket.listen(1)
# Socket Connection, IP Address of client
connection, ipAdd = serverSocket.accept()


# =-=-=-=-=-=-=-=-=-= Share RSA Public Key =-=-=-=-=-=-=-=-=-=
connection.send(public_rsa)



# =-=-=-=-=-=-=-=-=-= Diffie-Hellman Setup =-=-=-=-=-=-=-=-=-=
# q and a are agreed on numbers
# q in a prime while and a  is a premitive root of q
q, a = q, a
Xa = secrets.randbelow(q) # random number in bellow q
Ya = int(pow(a,Xa, q)) # calculate public key
# =-=-=-=-=-=-=-=-=-= Exchange Diffie-Hellman Public keys =-=-=-=-=-=-=-=-=-=
connection.send(str(Ya).encode())
Yb = int(takein(connection))
# =-=-=-=-=-=-=-=-=-= Diffie-Hellman Secret Key =-=-=-=-=-=-=-=-=-=
K = pow(Yb,Xa,q)
# print("Ya = ", Ya, "Yb = ", Yb)
print("Diffie-Hellman key:", K)


# =-=-=-=-=-=-=-=-=-= Recive Encoded Message =-=-=-=-=-=-=-=-=-=
cipherbin = takein(connection)
# =-=-=-=-=-=-=-=-=-= Decode Encoded Message =-=-=-=-=-=-=-=-=-=
cipher_int = int(cipherbin.decode())
decrypt_int = pow(cipher_int,key.d, key.n)
# The formula is to calculate to_bytes arguments 
# (decrypt.bit_length() + 7)//8) to find the number of bits needed to represent decrypt_int
plaintext = decrypt_int.to_bytes((decrypt_int.bit_length() + 7)//8).decode()
print(plaintext)


# =-=-=-=-=-=-=-=-=-= 1st Recive Encoded Message With Ingegrity =-=-=-=-=-=-=-=-=-=
cipherbin, signature = takein(connection).split(b"\n",1)
expectedSignature = hmac.new(str(K).encode(), cipherbin, hashlib.sha256).digest() + int.to_bytes(1)
# =-=-=-=-=-=-=-=-=-= Decode Encoded Message Ingegrity =-=-=-=-=-=-=-=-=-=
if (hmac.compare_digest(signature, expectedSignature)):
    cipher_int = int(cipherbin.decode())
    decrypt_int = pow(cipher_int,key.d, key.n)
    # The formula is to calculate to_bytes arguments 
    # (decrypt.bit_length() + 7)//8) to find the number of bits needed to represent decrypt_int
    plaintext = decrypt_int.to_bytes((decrypt_int.bit_length() + 7)//8).decode()
    print("First Attempt: ", plaintext)
else:
    print("not expected signature")

# =-=-=-=-=-=-=-=-=-= 2nd Recive Encoded Message With Ingegrity =-=-=-=-=-=-=-=-=-=
cipherbin, signature = takein(connection).split(b"\n",1)
expectedSignature = hmac.new(str(K).encode(), cipherbin, hashlib.sha256).digest()
# =-=-=-=-=-=-=-=-=-= Decode Encoded Message Ingegrity =-=-=-=-=-=-=-=-=-=
if (hmac.compare_digest(signature, expectedSignature)):
    cipher_int = int(cipherbin.decode())
    decrypt_int = pow(cipher_int,key.d, key.n)
    # The formula is to calculate to_bytes arguments 
    # (decrypt.bit_length() + 7)//8) to find the number of bits needed to represent decrypt_int
    plaintext = decrypt_int.to_bytes((decrypt_int.bit_length() + 7)//8).decode()
    print("Second Attempt: ", plaintext)
else:
    print("not expected signature")