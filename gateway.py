import socket
import threading
import pickle
from crypto_utils import generate_keypair, sign_data, create_certificate
from crypto_utils import deserialize_public_key, serialize_public_key
from messages import Certificate, CSR

class Gateway:
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.agents_certificates = {}  # Armazena certificados emitidos para os agentes
        self.public_key, self.private_key = generate_keypair()
        self.certificate = create_certificate("Gateway", self.public_key, self.private_key)

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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            while True:
                conn, addr = server_socket.accept()
                threading.Thread(target=self.handle_agent, args=(conn, addr)).start()
