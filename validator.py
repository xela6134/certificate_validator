import sys, socket, ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def extract_certificates(domain_name, port=443):
    """
    Extracts the certificate chain from a given domain name.
    
    Args:
        domain_name (str): The domain name to connect to.
        port (int): The port to connect to (default: 443).
    
    Returns:
        list: A list of certificates (x509 objects) in the chain.
    """
    certificates = []
    
    # Create an SSL context
    context = ssl.create_default_context()

    # Create a secure socket connection
    with socket.create_connection((domain_name, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
            
            # Attempt to fetch the full certificate chain (if supported)
            cert_chain = ssock.get_verified_chain()
            if not cert_chain:
                print(f"Cannot fetch certificate chain for {domain_name}. Attempting to fetch only leaf certificate")

                der_cert = ssock.getpeercert(binary_form=True)
                leaf_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                certificates.append(leaf_cert)

                return certificates

            for cert in cert_chain:
                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                certificates.append(cert_obj)
    
    return certificates

def validate_certificate(certificate):
    print(f"Type: {type(certificate)} - {certificate}")

def main():
    if len(sys.argv) == 1:
        print('Provide websites as command line arguments')
        sys.exit(1)
    
    for website in sys.argv[1:]:
        print(f"\nCertificate for {website}:")
        
        try:
            certificates = extract_certificates(website)
            for cert in certificates:
                validate_certificate(cert)
        except ConnectionResetError:
            print("Trying to connect to a forbidden website")
            continue
        except socket.gaierror:
            print("Host not known")
            continue

if __name__ == '__main__':
    main()
