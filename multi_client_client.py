import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from numpy import outer
import sys

ClientSocket = socket.socket()
host = '127.0.0.1'
port = 1233



def generate_keys():
    #modulus_lenght = 256*8
    privatekey = rsa.generate_private_key(public_exponent=(65537), 
                                          key_size=2048)
    publickey = privatekey.public_key()
    pem_public = publickey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    filename = f"multi_client_key{sys.argv[1]}.pem"
    with open(filename, "wb") as client_key:
        client_key.write(pem_public)
    
    return privatekey, publickey


privatekey, publickey = generate_keys()
with open("multi_server_key.pem", "rb") as server_key:
            public_key = serialization.load_pem_public_key(server_key.read())
print('Waiting for connection')
try:
    ClientSocket.connect((host, port))
except socket.error as e:
    print(str(e))

client_code = sys.argv[1]
cc = str.encode(f"{client_code}")
ClientSocket.sendall(cc)
while True:
    Input = str.encode(input('Message >>> '))
    ciphertext = public_key.encrypt(
                Input,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
    ClientSocket.sendall(ciphertext)
    #Response = ClientSocket.recv(2048)
    dados = ClientSocket.recv(2048)
    plaintext = privatekey.decrypt(
        dados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Server >> {plaintext}")
    #print(Response.decode('utf-8'))

ClientSocket.close()