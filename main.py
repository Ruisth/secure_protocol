import sys
from gateway import Gateway
from agent import Agent
from chat import Chat

if __name__ == "__main__":
    mode = input("Escolha o modo: 'gateway' ou 'agent': ").strip().lower()

    if mode == "gateway":
        gateway = Gateway()
        gateway.start()
    elif mode == "agent":
        name = input("Insira o nome do agente: ").strip()
        agent = Agent(name)
        agent.create_connection()
        agent.show_options()
    else:
        print("Modo inválido.")
