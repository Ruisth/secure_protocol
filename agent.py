import socket
import pickle
from crypto_utils import generate_keypair
from crypto_utils import serialize_public_key, deserialize_public_key
from messages import CSR

class Agent:
    def __init__(self, name, gateway_host='127.0.0.1', gateway_port=65432):
        self.name = name
        self.gateway_host = gateway_host
        self.gateway_port = gateway_port
        self.public_key, self.private_key = generate_keypair()
        self.certificate = None

    def request_certificate(self):
        """Solicitar um certificado da Gateway."""
        # Serializar a chave pública
        public_key_pem = serialize_public_key(self.public_key)
        csr = CSR(self.name, public_key_pem)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.gateway_host, self.gateway_port))
                
                # Enviar CSR para a Gateway
                client_socket.sendall(pickle.dumps(csr))

                # Receber resposta da Gateway
                response = client_socket.recv(4096)
                agent_certificate, gateway_certificate = pickle.loads(response)
                
                # Validar e armazenar os certificados recebidos
                self.certificate = agent_certificate
                print(f"Certificado recebido para o agente: {self.name}")
        except Exception as e:
            print(f"Erro ao solicitar certificado: {e}")
