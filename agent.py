import socket
import pickle
import os
import signal
import threading
import sys
from crypto_utils import *
from messages import CSR

class Agent:
    def __init__(self, name, gateway_host='127.0.0.1', gateway_port=65432):
        self.name = name
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.chat_port = gateway_port + 1  # Porta para escuta de outros agentes
        self.public_key, self.private_key = None, None
        self.certificate = None
        self.gateway_certificate = None
        self.listening_thread = None
        self.running = True  # Controle do loop de escuta
        
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
    
    
    # Aguarda conexões de outros agents
    def listen_for_connections(self):
        """Thread para escutar conexões de outros agentes."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((self.gateway_host, self.chat_port))
                server_socket.listen()
                print(f"🟢 {self.name} está à escuta em {self.gateway_host}:{self.chat_port}...")

                while self.running:
                    try:
                        conn, addr = server_socket.accept()
                        threading.Thread(target=self.handle_agent_connection, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue
        except Exception as e:
            print(f"Erro no servidor de escuta: {e}")
            

    # Lida com a conexão de um agente
    def handle_agent_connection(self, conn, addr):
        """Processar uma conexão de entrada de outro agente."""
        try:
            # Receber o certificado do agente remoto
            target_cert_bytes = pickle.loads(conn.recv(16384))
            target_cert = deserialize_certificate(target_cert_bytes)
            print(f"🔵 Certificado recebido de {addr}.")

            # Validar o certificado recebido
            if not validate_certificate(target_cert, self.gateway_certificate):
                raise ValueError("Certificado inválido recebido do agente remoto.")

            # Enviar o próprio certificado
            conn.sendall(pickle.dumps(serialize_certificate(self.certificate)))
            print(f"🔵 Certificado enviado para {addr}.")

            # Estabelecer chave secreta
            secret_key = os.urandom(32)
            encrypted_key = encrypt_with_public_key(secret_key, target_cert.public_key())
            conn.sendall(encrypted_key)
            print(f"🔵 Chave secreta compartilhada com {addr}.")

            # Iniciar chat seguro
            self.start_chat(target_cert, addr[0], addr[1])
        except Exception as e:
            print(f"Erro ao lidar com conexão de agente: {e}")
        finally:
            conn.close()
            
    
    # Troca de certificados com outros agents
    def exchange_certificates(self, target_host, target_port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Conectar ao agente alvo
                s.connect((target_host, target_port))
                print(f"Conectado ao agente em {target_host}:{target_port}")

                # Enviar certificado próprio
                s.sendall(pickle.dumps(serialize_certificate(self.certificate)))
                print("Certificado próprio enviado para o agente.")

                # Receber o certificado do agente alvo
                target_cert_bytes = pickle.loads(s.recv(16384))
                target_cert = deserialize_certificate(target_cert_bytes)
                print("Certificado do agente recebido.")

                # Validar certificado recebido usando chave pública da Gateway
                if not validate_certificate(target_cert, self.gateway_certificate):
                    raise ValueError("Certificado recebido não é válido.")
                print("Certificado do agente validado com sucesso!")

                return target_cert
        except Exception as e:
            print(f"Erro na troca de certificados: {e}")
            return None
        
        
    # Criação de chave simétrica
    def establish_secret_key(self, target_cert, target_host, target_port):
        try:
            # Gerar chave secreta simétrica
            secret_key = os.urandom(32)
            print("Chave secreta simétrica gerada.")

            # Cifrar chave secreta com a chave pública do agente alvo
            encrypted_key = encrypt_with_public_key(secret_key, target_cert.public_key())
            print("Chave secreta cifrada com a chave pública do agente alvo.")

            # Enviar chave cifrada
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_host, target_port))
                s.sendall(encrypted_key)
                print("Chave secreta cifrada enviada.")

            return secret_key
        except Exception as e:
            print(f"Erro ao estabelecer chave secreta: {e}")
            return None    
        
    
    # Ficar à espera de mensagens
    def listen_for_messages(self, secret_key):
        """Escuta continuamente mensagens cifradas."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind((self.gateway_host, self.gateway_port + 1))  # Porta dedicada à escuta
                server_socket.listen()
                print("🟢 A escutar mensagens... Pressione Ctrl+C para sair.")

                while True:
                    conn, addr = server_socket.accept()
                    with conn:
                        encrypted_message = conn.recv(16384)
                        if not encrypted_message:
                            continue
                        # Decifra mensagem
                        message = decrypt_message(secret_key, encrypted_message)
                        print(f"\n🔵 Mensagem recebida: {message}")
        except KeyboardInterrupt:
            print("\n🟡 A escuta foi interrompida. Retornando ao menu...")
        except Exception as e:
            print(f"Erro na escuta de mensagens: {e}")
        
    
    
    # Enviar mensagens
    def send_messages(self, secret_key, target_host, target_port):
        """Lê mensagens do terminal e as envia continuamente."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_host, target_port))
                print("🟢 Conectado para envio de mensagens. Escreva e pressione Enter para enviar:")
                while True:
                    message = input()  # Lê do terminal
                    if message.strip().lower() == "sair":
                        print("🟡 Encerrando envio de mensagens...")
                        break
                    # Cifra e envia mensagem
                    encrypted_message = encrypt_message(secret_key, message)
                    s.sendall(encrypted_message)
        except KeyboardInterrupt:
            print("\n🟡 Envio interrompido. Retornando ao menu...")
        except Exception as e:
            print(f"Erro no envio de mensagens: {e}")
    
    
    
    # Começar canal de chat entre agentes
    def start_chat(self, target_cert, target_host, target_port):
        """Inicia o chat seguro entre agentes."""
        try:
            # Estabelece a chave simétrica
            secret_key = self.establish_secret_key(target_cert, target_host, target_port)
            if not secret_key:
                print("🔴 Falha ao estabelecer a chave secreta.")
                return

            # Cria threads para escutar e enviar mensagens
            listener_thread = threading.Thread(target=self.listen_for_messages, args=(secret_key,), daemon=True)
            sender_thread = threading.Thread(target=self.send_messages, args=(secret_key, target_host, target_port))

            listener_thread.start()
            sender_thread.start()

            # Aguarda o término da thread de envio (Ctrl+C ou "sair")
            sender_thread.join()
        except KeyboardInterrupt:
            print("\n🟡 Encerrando chat seguro...")    
        
                    
    
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
                
                # Registrar agente
                self.register_with_gateway(client_socket)
                print("Registado na Gateway com sucesso!")
        
        except Exception as e:
            print(f"Erro ao criar conexão: {e}")
    
    
    # Registar agente com a Gateway        
    def register_with_gateway(self, client_socket):
        """Envia nome e porta para registrar o agente na gateway."""
        try:
            agent_info = (self.name, self.gateway_host, self.chat_port)
            client_socket.sendall(pickle.dumps(agent_info))
            print("Agente registrado com sucesso na Gateway!")
        except Exception as e:
            print(f"Erro ao registrar na Gateway: {e}")

    
    # Obter lista de agentes
    def get_agent_list(self, client_socket):
        """Solicita a lista de agentes conectados na Gateway."""
        try:
            client_socket.sendall("GET_AGENT_LIST".encode())
            agent_list = pickle.loads(client_socket.recv(16384))
            return agent_list
        except Exception as e:
            print(f"Erro ao obter lista de agentes: {e}")
            return []
        
    # Choose agent from list
    def choose_agent_from_list(self, client_socket):
        """Solicita a lista de agentes e permite ao usuário selecionar um."""
        try:
            # Solicita a lista de agentes conectados
            agent_list = self.get_agent_list(client_socket)
            if not agent_list:
                print("Nenhum agente disponível no momento.")
                return None, None

            # Mostra a lista ao usuário
            print("\nAgentes disponíveis:")
            for idx, (addr) in enumerate(agent_list):
                print(f"[{idx}] {addr}")

            # Solicita a escolha
            choice = int(input("\nEscolha um agente pelo número: ").strip())
            if 0 <= choice < len(agent_list):
                return agent_list[choice][1], agent_list[choice][2]  # Retorna IP e Porta
            else:
                print("Escolha inválida.")
                return None, None
        except Exception as e:
            print(f"Erro ao escolher agente: {e}")
            return None, None
            
    
    # Mostrar opções disponíveis        
    def show_options(self):
        print(" ")
        print("********************************************")
        print("*****   Bem vindo ao seu chat seguro!  *****")
        print("********************************************")
        print(" ")
        print("[1] - Iniciar chat com outro agente;")
        print("[2] - Renovar certificado;")
        print("[3] - Sair;")
        print(" ")
        
        option = input(f"{self.name}! Escolha uma opção: ")
        if option == "1":
            target_host = input("Insira o host do agente de destino: ").strip()
            target_port = int(input("Insira a porta do agente de destino: ").strip())
            target_cert = self.exchange_certificates(target_host, target_port)
            if target_cert:
                self.start_chat(target_cert, target_host, target_port)
        elif option == "2":
            self.create_connection()
            self.show_options()
        elif option == "3":
            self.running = False  # Parar escuta
            print("🟡 A sair...")
            # Terminar o terminal como se usasse o Control+C
            os.kill(os.getpid(), signal.SIGINT)
        else:
            print("Opção inválida. Tente novamente.")
            self.show_options()