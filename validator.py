import sys, socket, ssl, argparse, os, datetime
from cryptography import x509                                           # type: ignore
from cryptography.hazmat.backends import default_backend                # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding  # type: ignore
from cryptography.hazmat.primitives import serialization, hashes        # type: ignore

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
    
    # Create an SSL context that does not verify certificates
    # Ironically, you need an insecure connection to run this program
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # Create a secure socket connection
        with socket.create_connection((domain_name, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain_name) as ssock:
                
                # Attempt to fetch the full certificate chain (if supported)
                cert_chain = ssock.get_verified_chain()
                if not cert_chain:
                    print(f"Cannot fetch certificate chain for {domain_name}. Attempting to fetch only leaf certificate.")

                    der_cert = ssock.getpeercert(binary_form=True)
                    leaf_cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    certificates.append(leaf_cert)

                    return certificates

                for cert in cert_chain:
                    cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                    certificates.append(cert_obj)

    except Exception as e:
        print(f"Error fetching certificates for {domain_name}: {e}")

    return certificates

def validate_certificate(certificates, website_name):
    """
    Default validation logic for certificates.
    """
    # 1. Check certificate validity period
    for cert_depth, cert in enumerate(certificates):
        current_datetime = datetime.datetime.now(datetime.UTC)
        valid_before = cert.not_valid_before_utc
        valid_after = cert.not_valid_after_utc

        if valid_after < current_datetime:
            print(f"Certificate for {website_name} at depth {cert_depth} has expired.")
            return False
        elif valid_before > current_datetime:
            print(f"Certificate for {website_name} at depth {cert_depth} is valid from the future.")
            return False

    for depth, cert in enumerate(certificates):
        print(f"depth {depth}: {cert}")

    # 2. Validate certificate signatures
    for cert_depth in range(len(certificates) - 1):
        cert = certificates[cert_depth]
        issuer_cert = certificates[cert_depth + 1]

        try:
            issuer_public_key = issuer_cert.public_key()

            # Verify the certificate's signature
            # 1. Client hashes cert.tbs_certificate_bytes using cert.signature_hash_algorithm
            # 2. Client decrypts cert.signature using issuer_public_key
            # 3. If the hashes match, the signature is valid
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except Exception as e:
            print(f"Certificate for {website_name} at depth {cert_depth} failed signature verification: {e}")
            return False

    # Optionally, validate the root certificate's self-signature
    root_cert = certificates[-1]
    try:
        root_public_key = root_cert.public_key()
        root_public_key.verify(
            root_cert.signature,
            root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            root_cert.signature_hash_algorithm
        )
    except Exception as e:
        print(f"Root certificate self-signature verification failed: {e}")
        return False

    return True
    
def print_cryptography_info(certificates):
    """
    Prints cryptography-related information for certificates.
    """

    for depth, cert in enumerate(certificates):
        print(f"\nCertificate Cryptography Information in depth {depth}:")

        print(f"Subject         : {cert.subject}")
        print(f"Issuer          : {cert.issuer}")
        print(f"Serial No       : {cert.serial_number}")
        print(f"Not Valid Before: {cert.not_valid_before_utc}")
        print(f"Not Valid After : {cert.not_valid_after_utc}")
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
            print(f"X: {public_numbers.x}")
            print(f"Y: {public_numbers.y}")
        else:
            print("\nThe public key type is not supported.")

def download_certificates(certs, website_name):
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

    for website_name in args.websites:
        print(f"\nProcessing certificates for {website_name}:")
        
        try:
            certificates = extract_certificates(website_name)

            if validate_certificate(certificates, website_name) == True:
                print(f"Certificates all valid for {website_name}")
            
            # Additional Info
            if args.cryptography:
                print_cryptography_info(certificates)
                
            if args.download:
                download_certificates(certificates, website_name)

        except ConnectionResetError:
            print(f"Connection reset when trying to connect to {website_name}")
            continue
        except socket.gaierror:
            print(f"Host not known: {website_name}")
            continue

if __name__ == '__main__':
    main()
