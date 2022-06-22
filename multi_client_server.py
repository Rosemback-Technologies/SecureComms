from pydoc import plain
import socket
import os
from _thread import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from numpy import outer

ServerSocket = socket.socket()
host = '127.0.0.1'
port = 1233
ThreadCount = 0
try:
    ServerSocket.bind((host, port))
except socket.error as e:
    print(str(e))

print('Waitiing for a Connection..')
ServerSocket.listen(5)

def generate_keys():
    #modulus_lenght = 256*8
    privatekey = rsa.generate_private_key(public_exponent=(65537), 
                                          key_size=2048)
    publickey = privatekey.public_key()
    pem_public = publickey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("multi_server_key.pem", "wb") as server_key:
        server_key.write(pem_public)
    
    return privatekey, publickey


privatekey, publickey = generate_keys()


def threaded_client(connection):
    #connection.send(str.encode('Welcome to the Servern'))
    cc = connection.recv(2048).decode()
    print(cc)
    with open(f"multi_client_key{cc}.pem", "rb") as client_key:
            public_key = serialization.load_pem_public_key(client_key.read())
    while True:
        
        
        dados = connection.recv(2048)
        plaintext = privatekey.decrypt(
            dados,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Client >>> {plaintext}")
        reply = str.encode(input("Message >>> "))
        if plaintext == 'exit' or reply == 'exit':
            break
        ciphertext = public_key.encrypt(
            reply,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        connection.send(ciphertext)
    connection.close()
try:
    
    while True:
        Client, address = ServerSocket.accept()
        print('Connected to: ' + address[0] + ':' + str(address[1]))
        start_new_thread(threaded_client, (Client, ))
        ThreadCount += 1
        print('Thread Number: ' + str(ThreadCount))
    ServerSocket.close()
except Exception as e:
    print(str(e))