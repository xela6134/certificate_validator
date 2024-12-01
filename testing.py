import certifi

# Get the path to the trusted root certificates
cert_path = certifi.where()
print(f"Trusted root certificates are located at: {cert_path}")

from cryptography import x509
from cryptography.hazmat.primitives import serialization

def load_trusted_root_certificates(cert_path):
    with open(cert_path, "rb") as cert_file:
        pem_data = cert_file.read()
    
    # Split the file into individual certificates
    trusted_certs = []
    for cert_pem in pem_data.split(b"-----END CERTIFICATE-----"):
        if cert_pem.strip():  # Ensure it's not empty
            cert_pem += b"-----END CERTIFICATE-----"
            cert = x509.load_pem_x509_certificate(cert_pem)
            trusted_certs.append(cert)
    return trusted_certs

# Load the trusted certificates
cert_path = certifi.where()
trusted_certs = load_trusted_root_certificates(cert_path)

# Print details about the trusted certificates
print(f"Loaded {len(trusted_certs)} trusted root certificates.")
for i, cert in enumerate(trusted_certs[:5]):  # Print details for the first 5 certificates
    print(f"Type: {type(cert)}")
    print(f"Certificate {i+1}:")
    print(f"  Subject: {cert.subject}")
    print(f"  Issuer: {cert.issuer}")
    print(f"  Serial Number: {cert.serial_number}")
