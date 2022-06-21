
from socket import *
from sys import argv
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from sympy import public


def generate_keys():
    #modulus_lenght = 256*8
    privatekey = rsa.generate_private_key(public_exponent=(65537), 
                                          key_size=2048)
    publickey = privatekey.public_key()
    pem_public = publickey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("client_key.pem", "wb") as client_key:
        
        client_key.write(pem_public)
    return privatekey, publickey

def client2(port, publickey, privatekey, password):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect(('127.0.0.1', port))
    #send = f"####################Connection Established!####################".encode()
    #sock.sendall(send)
    pem = privatekey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"senhaDeTeste")
    )
    

    while True:
        with open("server_key.pem", "rb") as server_key:
            public_key = serialization.load_pem_public_key(server_key.read())
        
        message = str.encode(input("Message >>> "))
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #print("Ciphertext")
        #print(ciphertext)
        sock.sendall(ciphertext)
        dados = sock.recv(2048)
        plaintext = privatekey.decrypt(
            dados,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Client >>> {plaintext}")
        if plaintext == "sair":
            sock.close()
            break
        print(f"Server >>> {plaintext}")
        

        
        
input_port = argv[1]
password = argv[2]
try:
    input_port = int(input_port)
    privatekey, publickey = generate_keys()
    print(f"conectando ao servidor na porta: {input_port}")
    while True:
        try:
            client2(input_port, publickey, privatekey, password)
        except Exception as e:
            print(str(e))
            time.sleep(3)
            print("------retrying to connect------")
            continue
except Exception as e:
    print(str(e))
    