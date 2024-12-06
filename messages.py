class CSR:
    def __init__(self, agent_name, public_key_pem):
        self.agent_name = agent_name
        self.public_key_pem = public_key_pem

class Certificate:
    def __init__(self, name, public_key_pem, signature):
        self.name = name
        self.public_key_pem = public_key_pem
        self.signature = signature
