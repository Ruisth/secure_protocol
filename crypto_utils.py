import datetime
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from messages import Certificate


def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key


def encrypt_private_key(private_key, password):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )


def sign_data(data, private_key):
    return private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

# create a certificate with the name, expiration date, public key and issuer private key to sign the certificate
def create_certificate(name, public_key, expiration_date, issuer_private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, name),
        x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, str(datetime.datetime.now(datetime.timezone.utc))),
        x509.NameAttribute(x509.NameOID.POSTAL_CODE, str(expiration_date)),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, str(public_key))
    ])
    builder = x509.CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        public_key=public_key,
        serial_number=random.randint(1, 1000000),
        not_valid_before=datetime.datetime.now(datetime.timezone.utc),
        not_valid_after=expiration_date,
    )
    signature = builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
    return Certificate(name, public_key, expiration_date, signature)


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
