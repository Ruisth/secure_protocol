import socket
import threading

class Chat:
    def __init__(self, host='0.0.0.0', port=0):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}

    def start_server(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Servidor de chat iniciado na porta {self.server_socket.getsockname()[1]}")

        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Conexão de chat recebida de {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()

    def handle_client(self, client_socket, addr):
        try:
            self.clients[addr] = client_socket
            while True:
                message = client_socket.recv(1024).decode()
                if message:
                    print(f"Mensagem recebida de {addr}: {message}")
                    self.broadcast_message(message, addr)
                else:
                    break
        except Exception as e:
            print(f"Erro ao lidar com o cliente de chat {addr}: {e}")
        finally:
            client_socket.close()
            del self.clients[addr]

    def broadcast_message(self, message, sender_addr):
        for addr, client_socket in self.clients.items():
            if addr != sender_addr:
                try:
                    client_socket.sendall(message.encode())
                except Exception as e:
                    print(f"Erro ao enviar mensagem para {addr}: {e}")

    def start(self):
        threading.Thread(target=self.start_server).start()
        