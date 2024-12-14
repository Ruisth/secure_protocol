import sys
from gateway import Gateway
from agent import Agent

if __name__ == "__main__":
    mode = input("Escolha o modo: 'gateway' ou 'agent': ").strip().lower()

    if mode == "gateway":
        server = Gateway()
        server.start()
    elif mode == "agent":
        name = input("Insira o nome do agente: ").strip()
        agent = Agent(name)
        agent.create_connection()
        agent.show_options()
    else:
        print("Modo inválido.")
