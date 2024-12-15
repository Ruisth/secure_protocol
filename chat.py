import socket
import threading
import signal
import sys
import json
from agent import Agent

class Chat:
    def __init__(self):
        self.host = None
        self.port = None
        self.clients = []
        self.client_names = []
    
    
    # Obtem o host e a porta do servidor de chat
    def get_host(self):
        return self.host
    
    def get_port(self):
        return self.port
    
    
    # Adiciona um cliente ao chat    
    def add_client(self, conn, addr):
        try:
            # Receber o nome do cliente
            name = conn.recv(1024).decode('utf-8').strip()
            if name:
                print(f"Cliente '{name}' conectado de {addr}")
                self.client_names.append(name)
                self.clients.append((conn, name))  # Associa socket ao nome
        except Exception as e:
            print(f"Erro ao lidar com o cliente {addr}: {e}")
        # Mostra o array de clientes
        print(f"Clientes conectados: {self.clients}")
        print(f"Nomes dos clientes: {self.client_names}")
    
    
    # Remove um cliente do chat
    def remove_client(self, client_socket, client_address):
        pass

    
    # Troca de mensagens entre os clientes    
    def change_messages(self, client_socket, client_address):
        pass
    
    
    # Lida com os clientes
    def handle_client(self, conn, addr):
        # Conexão estabelecida com o cliente
        print(f"Conexão estabelecida com o cliente {addr}")
        
    
    
    # Inicia o servidor de chat
    def start_chat(self): 
        
        # Pede input de um host e de um port
        print(" ")
        input_host = input("Insira o host do servidor de chat (ex: 127.0.0.2): ").strip()
        input_port = int(input("Insira a porta do servidor de chat (ex.65433): ").strip())
        
        # Verifica se o host e a porta estão disponíveis e atribui-os
        if input_host or input_port:
            self.host = input_host
            self.port = input_port
            
        print(f"Servidor de chat iniciado em {self.host}:{self.port}")
            
        # Adiciona o tratamento de sinal para capturar o Ctrl+C
        def signal_handler(sig, frame):
            print("\nInterrompendo o chat...")
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
                    threading.Thread(target=self.handle_client, args=(conn, addr)).start()
                except socket.timeout:
                    # Se o timeout ocorrer, simplesmente continuar a execução e verificar sinais
                    continue
                except Exception as e:
                    print(f"Erro na aceitação de conexão: {e}")
            

        