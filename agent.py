import socket
import threading
import pickle
import os
import signal
import sys
import datetime
from crypto_utils import *
from chat import *
from messages import CSR

class Agent:
    def __init__(self, name, gateway_host='127.0.0.1', gateway_port=65432):
        self.name = name
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.public_key, self.private_key = generate_keypair()
        self.certificate = None
        self.gateway_certificate = None
        
        # senha secreta aleatória
        secret_key = os.urandom(32)
        agent_enc_pr_key = encrypt_private_key(self.private_key, secret_key)     
        print("Chave privada encriptada guardada com sucesso! ")

    """Enviar chave pública para a Gateway."""
    def send_public_key(self, client_socket):
        try:
            public_key_bytes = serialize_public_key(self.public_key)
            print(f"Public Key Bytes: {public_key_bytes}")  # Debug message
            client_socket.sendall(pickle.dumps(public_key_bytes))
            print("Chave pública enviada com sucesso! ")
        except Exception as e:
            print(f"Erro ao enviar chave pública: {e}")
        
        
    def request_certificate(self, client_socket):
        """Solicitar um certificado da Gateway."""
        # Criar um CSR
        csr = CSR(self.name, serialize_public_key(self.public_key))
        try:
            print(f"CSR: {csr}")  # Debug message
            client_socket.sendall(pickle.dumps(csr))
            print("CSR enviado com sucesso! ")
        
            # Receber os certificados do agente
            serialized_certificate = pickle.loads(client_socket.recv(16384))
            self.certificate = deserialize_certificate(serialized_certificate)
            
            print("Certificado do agente recebido!")  # Debug message
            
            # Enviar ACK para a Gateway
            client_socket.sendall(b"ACK")
            print("ACK enviado para a gateway! ")
            
            # Receber o certificado da Gateway
            serialized_gateway_certificate = pickle.loads(client_socket.recv(16384))
            self.gateway_certificate = deserialize_certificate(serialized_gateway_certificate)
            
            print("Certificados recebidos com sucesso! ")
            
            # Armazenar o certificado do agente num ficheiro
            with open(f"{self.name}_cert.pem", "wb") as cert_file:
                cert_file.write(self.certificate.public_bytes(serialization.Encoding.PEM))
            print(f"Certificado guardado em {self.name}_cert.pem")
        
        except Exception as e:
            print(f"Erro ao solicitar certificado: {e}")
            
    
    """Criar conexão com a Gateway."""
    def create_connection(self):
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.gateway_host, self.gateway_port))
                print("Conexão criada com sucesso! ")
        
                #Enviar chave pública para a Gateway.
                self.send_public_key(client_socket)
                
                #Obter ack da Gateway
                ack = client_socket.recv(1024)
                if ack != b"ACK":
                    raise ValueError("Erro ao receber ACK da Gateway")
                print("ACK recebido com sucesso! ")
        
                #Solicitar um certificado da Gateway.
                self.request_certificate(client_socket)
                
                # Troca de certificados concluída
                print("Troca de certificados concluída com sucesso!")
        
        except Exception as e:
            print(f"Erro ao criar conexão: {e}")
            
    # Criar o chat seguro
    def create_chat(self):
        chat = Chat()
        chat.start()
        
            
    def show_options(self):
        print(" ")
        print("********************************************")
        print("*****   Bem vindo ao seu chat seguro!  *****")
        print("********************************************")
        print(" ")
        print("[1] - Criar novo chat;")
        print("[2] - Procurar chats existentes;")
        print("[3] - Renovar certificado;")
        print(" ")
        
        option = input(f"{self.name}! Escolha a opção pretendida: ")
        if option == "1":
            self.create_chat()
        elif option == "2":
            self.search_chats()
        elif option == "3":
            self.create_connection()
            self.show_options()
        else:
            print("Opção inválida.")
            self.show_options()
        # Adicione mais opções conforme necessário
