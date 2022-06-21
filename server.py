from socket import *
from sys import argv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from numpy import outer


def generate_keys():
    #modulus_lenght = 256*8
    privatekey = rsa.generate_private_key(public_exponent=(65537), 
                                          key_size=2048)
    publickey = privatekey.public_key()
    pem_public = publickey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("server_key.pem", "wb") as server_key:
        server_key.write(pem_public)
    
    return privatekey, publickey


def serve(port, pubkey, privkey):
    server = socket(AF_INET, SOCK_STREAM)
    server.bind(("0.0.0.0", port)) 
    server.listen(5)
    client,addr = server.accept()

    print(f"Connected from {addr}")
    while True:    
        with open("client_key.pem", "rb") as client_key:
            public_key = serialization.load_pem_public_key(client_key.read())
        dados = client.recv(2048)
        plaintext = privatekey.decrypt(
            dados,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Client >>> {plaintext}")
        message = str.encode(input("Message >>> "))
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client.sendall(ciphertext)
        if plaintext == "au revoir":
            client.close
            break
        server.close()
        
input_port = argv[1]

try:
    input_port = int(input_port)
    privatekey, publickey = generate_keys()
    print("Iniciando server na porta {}".format(input_port))
    serve(input_port, publickey, privatekey)
except Exception as e:
    print(f"Porta {input_port} não suportada.")
    print(e)