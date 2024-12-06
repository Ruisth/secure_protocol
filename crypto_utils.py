from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from messages import Certificate

def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key

def sign_data(data, private_key):
    return private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

def create_certificate(name, public_key, issuer_private_key, issuer_public_key=None):
    cert_data = f"{name}".encode()
    signature = sign_data(cert_data, issuer_private_key)
    return Certificate(name, public_key, signature)

def serialize_public_key(public_key):
    """Serializa a chave pública em formato PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    """Desserializa a chave pública a partir do formato PEM."""
    return serialization.load_pem_public_key(pem_data)

def serialize_private_key(private_key):
    """Serializa a chave privada em formato PEM."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_private_key(pem_data):
    """Desserializa a chave privada a partir do formato PEM."""
    return serialization.load_pem_private_key(pem_data, password=None)
