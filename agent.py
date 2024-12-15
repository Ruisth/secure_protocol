import socket
import pickle
import os
import signal
from crypto_utils import *
from messages import CSR

class Agent:
    def __init__(self, name, gateway_host='127.0.0.1', gateway_port=65432):
        self.name = name
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.chat_host = None
        self.chat_port = None
        self.public_key, self.private_key = None, None
        self.certificate = None
        self.gateway_certificate = None
        
    def generate_key_pair(self):
        # Gerar um par de chaves RSA
        self.public_key, self.private_key = generate_keypair()
        print("Par de chaves gerado com sucesso! ")
        
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
    
    
    # Troca de certificados com outros agents
    def exchange_certificates_with_agents(self, client_socket):
        try:
             # Solicitar informações dos outros dois agentes
            peer_names = [name for name in self.client_names if name != self.name]  # Ignora o próprio nome
            peer_certificates = {}

            for peer_name in peer_names:
                # Obter o host e a porta do agente alvo
                target_host, target_port = self.request_peer_info(peer_name, client_socket)
                if target_host:
                    print(f"Conectando ao agente {peer_name} em {target_host}:{target_port}...")
                    
                    # Conectar diretamente com o agente alvo e trocar certificados
                    target_certificate = self.exchange_certificates(target_host, target_port)
                    if target_certificate:
                        peer_certificates[peer_name] = target_certificate
                else:
                    print(f"Não foi possível encontrar o agente {peer_name}")

            return peer_certificates
        except Exception as e:
            print(f"Erro ao trocar certificados com os pares: {e}")
            return None    
        
        
    # Aguarda pelos certificados dos outros agents    
    def wait_for_certificates_from_peers(self):
        try:
            # Abrir um socket para aceitar conexões
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((self.chat_host, self.chat_port))
                server_socket.listen(2)  # Espera por dois outros agentes
                print(f"Aguardando conexões para troca de certificados em {self.chat_host}:{self.chat_port}")
                
                peer_certificates = {}

                for _ in range(2):  # Espera por 2 conexões (dos outros dois agentes)
                    conn, addr = server_socket.accept()
                    with conn:
                        print(f"Conexão estabelecida com {addr}")
                        
                        # Receber o certificado do outro agente
                        peer_certificate = pickle.loads(conn.recv(16384))
                        peer_name = conn.recv(1024).decode('utf-8').strip()  # Nome do agente
                        peer_certificates[peer_name] = peer_certificate
                        print(f"Certificado recebido de {peer_name}")
                        
                        # Enviar o próprio certificado para o agente
                        conn.sendall(pickle.dumps(self.certificate))
                        print("Certificado enviado.")
                    
                return peer_certificates
        except Exception as e:
            print(f"Erro ao esperar por troca de certificados: {e}")
            return None
        
    
    # Juntar-se ao chat
    def join_chat(self):
        
        #Pede input para inserir o host e a porta do chat a que se pretende juntar
        print(" ")
        input_chat_host = input("Insira o host do chat pretendido (ex: 127.0.0.2): ").strip()
        input_chat_port = int(input("Insira a porta do chat pretendido (ex: 65433): ").strip())
        
        # Verifica se o host e a porta estão disponíveis e atribui-os
        if input_chat_host or input_chat_port:
            self.chat_host = input_chat_host
            self.chat_port = input_chat_port
        
        print(f" Conectado ao chat Host: {self.chat_host}, Port: {self.chat_port}")
        
        try:
            # Enviar o nome do agente e o host e port para o chat
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.chat_host, self.chat_port))
                print("Conexão com o chat estabelecida com sucesso! ")
                
                # Enviar o nome do agente para o servidor de chat
                client_socket.sendall(self.name.encode('utf-8'))
                print(f"Nome do agente '{self.name}' enviado ao servidor de chat.")
                
        except Exception as e:
            print(f"Erro ao juntar-se ao chat: {e}")
            
    
    """Criar conexão com a Gateway."""
    def create_connection(self):
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.gateway_host, self.gateway_port))
                print("Conexão criada com sucesso! ")
                
                # Gerar novas chaves RSA
                self.generate_key_pair()
        
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
            
    
    # Mostrar opções disponíveis        
    def show_options(self):
        print(" ")
        print("********************************************")
        print("*****   Bem vindo ao seu chat seguro!  *****")
        print("********************************************")
        print(" ")
        print("[1] - Conectar a um chat;")
        print("[2] - Renovar certificado;")
        print("[3] - Sair;")
        print(" ")
        
        option = input(f"{self.name}! Escolha a opção pretendida: ")
        if option == "1":
            self.join_chat()
        elif option == "2":
            self.create_connection()
            self.show_options()
        elif option == "3":
            # Terminar o terminal como se usasse o Control+C
            os.kill(os.getpid(), signal.SIGINT)
        else:
            print("Opção inválida.")
            self.show_options()