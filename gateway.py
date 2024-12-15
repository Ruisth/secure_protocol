import socket
import threading
import pickle
import os
import signal
import sys
import datetime
from crypto_utils import *
from messages import Certificate, CSR


class Gateway:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.agents_certificates = {}  # Armazena certificados emitidos para os agentes
        self.agents_public_keys = {}  # Armazena chaves públicas dos agentes
        self.registered_agents = {}  # {address: (name, ip, port)}
        self.public_key, self.private_key = generate_keypair()
        
        # senha secreta aleatória
        secret_key = os.urandom(32)
        gateway_enc_pr_key = encrypt_private_key(self.private_key, secret_key)     
        print("Chave privada encriptada guardada com sucesso! ")
        
        # Criação da expiration_date para expirar após 1 hora da criação do certificado
        self.expiration_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        
        self.certificate = create_certificate("Gateway", self.public_key, self.expiration_date, self.private_key)
        saved_certificate = self.certificate
        print("Certificado do Gateway criado com sucesso! ")
        
        # Guardar o certificado num ficheiro
        with open("gateway_cert.pem", "wb") as cert_file:
            cert_file.write(saved_certificate.public_bytes(serialization.Encoding.PEM))
        print("Certificado guardado em gateway_certificate.pem")
        
    def get_public_key(self):
        return self.public_key
    
    
    def receive_agent_key(self, conn, addr):
        # Receber chave pública do agente
        try:
            data = conn.recv(16384)
            print(f"Raw data received from {addr}: {data}")  # Debug message
            agent_public_key = pickle.loads(data)
            print("Chave pública recebida e carregada com sucesso! ")
            self.agents_public_keys[addr] = deserialize_public_key(agent_public_key)
        except Exception as e:
            print(f"Erro ao receber chave pública do agente: {e}")
            
            
    def receive_agent_cert_request(self, conn, addr):
        # Receber CSR do agente
        try:
            csr = pickle.loads(conn.recv(16384))
            print(f"CSR Received: {csr}")  # Debug message
            csr_agent_name = csr.agent_name
            csr_public_key = deserialize_public_key(csr.public_key)
            # Verificar se a public key no CSR é igual à public key recebida
            if csr_public_key != self.agents_public_keys[addr]:
                raise ValueError("A chave pública no CSR " + {csr_public_key} + " não corresponde à chave pública recebida" + {self.agents_public_keys[addr]})
            print(f"CSR do agente {addr} recebido com sucesso! ")
            
            # Criar um certificado para o agente
            print(f"Agent Name: {csr.agent_name}")
            print(f"Public Key: {csr_public_key}")
            agent_certificate = create_certificate(csr_agent_name, csr_public_key, self.expiration_date, self.private_key)
            print(f"Certificado do agente {addr} criado com sucesso! ")
            
            # Guardar o certificado do agente
            self.agents_certificates[addr] = agent_certificate
            
            serialized_agent_certificate = serialize_certificate(agent_certificate)
            serialized_gateway_certificate = serialize_certificate(self.certificate)
            
            # Enviar o certificado deste agente e da gateway para o agente
            conn.sendall(pickle.dumps(serialized_agent_certificate))
            print("Certificado do agente enviado!")  # Debug message
            # Solicitar ACK do agente
            ack = conn.recv(1024)
            if ack != b"ACK":
                raise ValueError("Erro ao receber ACK do agente")
            print("ACK recebido com sucesso! ")
            
            # Enviar o certificado da Gateway para o agente
            conn.sendall(pickle.dumps(serialized_gateway_certificate))
            print(f"Certificados enviados para o agente {addr}, {csr_agent_name} ")
        
        except Exception as e:
            print(f"Erro ao receber CSR do agente {addr}: {e}")
        

    # regista um agente
    def register_agent(self, addr):
        """Registra um agente na lista de agentes conectados."""
        try:
            self.registered_agents[addr] = (addr)
            print(f"Agente registado: {addr}")
        except Exception as e:
            print(f"Erro ao registar o agente {addr}: {e}")
    

    def handle_agent(self, conn, addr):
        """Processar uma conexão de agente e emitir um certificado."""
        try:
            #Receber conexão do agente
            print(" ")
            print(f"Conexão estabelecida com o agente {addr}")
            
            # Receber a chave pública do agente
            self.receive_agent_key(conn, addr)
            
            # Enviar ACK para o agente
            conn.sendall(b"ACK")
            print("ACK enviado para o agente! ")
            
            # Receber o CSR do agente e emitir um certificado
            self.receive_agent_cert_request(conn, addr)
            
            # Registrar agente
            self.register_agent(addr)

        except Exception as e:
            print(f"Erro ao lidar com o agente {addr}: {e}")
        finally:
            conn.close()


    def start(self):
        print(f"Servidor Gateway iniciado em {self.host}:{self.port}")
        
        # Adiciona o tratamento de sinal para capturar o Ctrl+C
        def signal_handler(sig, frame):
            print("\nInterrompendo a gateway...")
            sys.exit(0)  # Termina o programa

        # Registra o manipulador para o sinal SIGINT (Ctrl+C)
        signal.signal(signal.SIGINT, signal_handler)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            server_socket.settimeout(1)
            
            while True:
                try:
                    conn, addr = server_socket.accept()
                    threading.Thread(target=self.handle_agent, args=(conn, addr)).start()
                except socket.timeout:
                    # Se o timeout ocorrer, simplesmente continuar a execução e verificar sinais
                    continue
                except Exception as e:
                    print(f"Erro na aceitação de conexão: {e}")
