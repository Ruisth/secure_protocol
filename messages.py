class CSR:
    def __init__(self, agent_name, public_key):
        self.agent_name = agent_name
        self.public_key = public_key

class Certificate:
    def __init__(self, name, public_key, expiration_date, signature):
        self.name = name
        self.public_key = public_key
        self.expiration_date = expiration_date
        self.signature = signature
