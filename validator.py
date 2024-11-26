import sys, socket, ssl, argparse, os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

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
    
    # Secure connection made through SSL Protocol
    context = ssl.create_default_context()

    # Creating secure socket connection
    with socket.create_connection((domain_name, port)) as sock:
        with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
            
            # Attempt to fetch the full certificate chain (if supported)
            cert_chain = ssock.get_verified_chain()
            if not cert_chain:
                print(f"Cannot fetch certificate chain for {domain_name}. Attempting to fetch only leaf certificate")

                der_cert = ssock.getpeercert(binary_form=True)
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
                
                leaf_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                certificates.append(leaf_cert)

                return certificates

            for cert in cert_chain:
                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                certificates.append(cert_obj)
    
    return certificates

def validate_certificate(cert):
    """
    Default validation logic for certificates.
    """
    print(f"Type: {type(cert)} - {cert}")

def print_cryptography_info(cert):
    """
    Prints cryptography-related information for certificates.
    """
    print("\nRoot Certificate Cryptography Information:")

    print(f"Subject         : {cert.subject}")
    print(f"Issuer          : {cert.issuer}")
    print(f"Serial No       : {cert.serial_number}")
    print(f"Not Valid Before: {cert.not_valid_before}")
    print(f"Not Valid After : {cert.not_valid_after}")
    print(f"Hash Algorithm  : {cert.signature_hash_algorithm}")

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        # Handle RSA key
        public_numbers = public_key.public_numbers()
        print("\nRaw RSA Public Key Components)")
        print(f"Modulus (n): {public_numbers.n}")
        print(f"Public Exponent (e): {public_numbers.e}")
        print(f"Key Size: {public_key.key_size} bits")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        # Handle ECC key
        public_numbers = public_key.public_numbers()
        curve = public_key.curve.name       # Get the curve name (e.g., secp256r1)
        print("\nElliptic Curve Public Key Components)")
        print(f"Curve: {curve}")
        print(f"X: {public_numbers.x}")     # X-coordinate of the public key
        print(f"Y: {public_numbers.y}")     # Y-coordinate of the public key
    else:
        print("\nThe public key type is not supported.")

def download_certificates(certs, website_name):
    cert_depth = 0

    if not os.path.exists('downloads'):
        os.mkdir('downloads')

    for cert in certs:
        pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()

        filename = f"{website_name}_{cert_depth}.pem"
        filepath = os.path.join('downloads', filename)
        
        with open(filepath, 'w') as cert_file:
            cert_file.write(pem_data)
        
        cert_file.close()
        cert_depth += 1
        
def main():
    parser = argparse.ArgumentParser(description="Certificate Validator Program")
    parser.add_argument("websites", nargs="*", help="List of websites to validate certificates for")
    parser.add_argument("-c", "--cryptography", action="store_true", help="Print cryptography information for leaf certificate")
    parser.add_argument("-d", "--download", action="store_true", help="Download each certificate in the chain in .pem format")
    args = parser.parse_args()

    if not args.websites:
        print("No websites provided. Use the -h flag for help.")
        sys.exit(1)

    for website in args.websites:
        print(f"\nProcessing certificates for {website}:")
        
        try:
            certificates = extract_certificates(website)

            for cert in certificates:
                validate_certificate(cert)

            # Additional Info
            if args.cryptography:
                print_cryptography_info(certificates[0])
                
            if args.download:
                download_certificates(certificates, website)

        except ConnectionResetError:
            print(f"Connection reset when trying to connect to {website}")
            continue
        except socket.gaierror:
            print(f"Host not known: {website}")
            continue

if __name__ == '__main__':
    main()
