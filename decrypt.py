from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

def decrypt_certificate():
    file_path = input("Digite o nome do ficheiro do certificado: ")
    with open(file_path, "rb") as cert_file:
        cert_data = cert_file.read()
    
    certificate = load_pem_x509_certificate(cert_data)
    return certificate

def print_certificate_details(certificate):
    print(f"Subject: {certificate.subject}")
    print(f"Issuer: {certificate.issuer}")
    print(f"Serial Number: {certificate.serial_number}")
    print(f"Not Valid Before: {certificate.not_valid_before}")
    print(f"Not Valid After: {certificate.not_valid_after}")
    print(f"Public Key: {certificate.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}")
    print(f"Extensions: {certificate.extensions}")

# Exemplo de uso
if __name__ == "__main__":
    cert = decrypt_certificate()
    print_certificate_details(cert)