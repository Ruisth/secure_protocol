import sys
from gateway import Gateway
from agent import Agent
from chat import Chat

if __name__ == "__main__":
    mode = input("Escolha o modo: 'gateway', 'agent' ou 'chat': ").strip().lower()

    if mode == "gateway":
        gateway = Gateway()
        gateway.start()
    elif mode == "agent":
        name = input("Insira o nome do agente: ").strip()
        agent = Agent(name)
        agent.create_connection()
        agent.show_options()
    elif mode == "chat":
        chat = Chat()
        chat.start_chat()
    else:
        print("Modo inválido.")
