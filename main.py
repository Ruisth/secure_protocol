import sys
from gateway import Gateway
from agent import Agent

if __name__ == "__main__":
    mode = input("Escolha o modo: 'server' (Gateway) ou 'agent': ").strip().lower()

    if mode == "server":
        server = Gateway()
        server.start()
    elif mode == "agent":
        name = input("Insira o nome do agente: ").strip()
        agent = Agent(name)
        agent.request_certificate()
    else:
        print("Modo inválido.")
