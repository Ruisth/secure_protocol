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
        self.public_key, self.private_key = generate_keypair()
        
        # senha secreta aleatória
        secret_key = os.urandom(32)
        encrypted_private_key = encrypt_private_key(self.private_key, secret_key)     
        print("Chave privada encriptada guardada com sucesso! ")
        
        # Criação da expiration_date para expirar após 1 hora da criação do certificado
        self.expiration_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        
        self.certificate = create_certificate("Gateway", self.public_key, self.expiration_date, self.private_key)
        certificate_pem = self.certificate.public_bytes(
            encoding=serialization.Encoding.PEM
            )
        with open("gateway_cert.pem", "wb") as file:
            f.write(certificate_pem)
        print("Certificado do Gateway criado com sucesso! ")
        
    def get_public_key(self):
        return self.public_key
        

    def handle_agent(self, conn, addr):
        """Processar uma conexão de agente e emitir um certificado."""
        try:
            # Receber CSR do agente
            csr = pickle.loads(conn.recv(4096))
            if isinstance(csr, CSR):
                print(f"Recebido CSR do agente {csr.agent_name}")

                # Desserializar a chave pública do CSR
                agent_public_key = deserialize_public_key(csr.public_key_pem)

                # Gerar certificado do agente
                agent_certificate = Certificate(
                    name=csr.agent_name,
                    public_key_pem=serialize_public_key(agent_public_key),
                    signature=sign_data(csr.agent_name.encode(), self.private_key)
                )
                self.agents_certificates[csr.agent_name] = agent_certificate

                # Enviar certificados de volta ao agente
                response = pickle.dumps((agent_certificate, self.certificate))
                conn.sendall(response)
                print(f"Certificado emitido para o agente: {csr.agent_name}")
        except Exception as e:
            print(f"Erro ao lidar com o agente {addr}: {e}")
        finally:
            conn.close()

    def start(self):
        print(f"Servidor Gateway iniciado em {self.host}:{self.port}")
        
        # Adiciona o tratamento de sinal para capturar o Ctrl+C
        def signal_handler(sig, frame):
            print("\nInterrompendo o servidor...")
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
