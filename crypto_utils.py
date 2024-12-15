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
from cryptography.x509.oid import NameOID


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
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Gateway"),
    ])
    
    builder = x509.CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        public_key=public_key,
        serial_number=random.randint(1, 1000000),
        not_valid_before=datetime.datetime.now(datetime.timezone.utc),
        not_valid_after=expiration_date,
    )
    
    # Add extensions for additional information
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(name)]),
        critical=False,
    )
    
    # Sign the certificate with the issuer's private key
    certificate = builder.sign(private_key=issuer_private_key, algorithm=hashes.SHA256())
    
    return certificate


# Serialization for public key
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
# Deserialization for public key
def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())


# Serialization of certificate
def serialize_certificate(certificate):
    return certificate.public_bytes(serialization.Encoding.PEM)


# Deserialization of certificate
def deserialize_certificate(certificate_bytes):
    return x509.load_pem_x509_certificate(certificate_bytes)


    
