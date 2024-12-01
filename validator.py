import sys, socket, ssl, argparse, os, datetime
import certifi                                                          # type: ignore
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

def load_trusted_root_certificates():
    cert_path = certifi.where()
    
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

def validate_certificate_validity(certificates, website_name):
    """
    Checks if each certificate in the chain is within its validity period.
    """
    current_datetime = datetime.datetime.now(datetime.UTC)

    for cert_depth, cert in enumerate(certificates):
        valid_before = cert.not_valid_before_utc
        valid_after = cert.not_valid_after_utc

        if valid_after < current_datetime:
            print(f"Certificate for {website_name} at depth {cert_depth} has expired.")
            return False
        elif valid_before > current_datetime:
            print(f"Certificate for {website_name} at depth {cert_depth} is valid from the future.")
            return False

    return True


def validate_certificate_signatures(certificates, website_name):
    """
    Validates the signature of each certificate against the issuer's public key.
    """
    for cert_depth in range(len(certificates) - 1):
        cert = certificates[cert_depth]
        issuer_cert = certificates[cert_depth + 1]

        try:
            issuer_public_key = issuer_cert.public_key()
            
            if isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm)
                )
            else:
                print(f"Unsupported public key type for certificate at depth {cert_depth}.")
                return False
        except Exception as e:
            print(f"Certificate for {website_name} at depth {cert_depth} failed signature verification: {e}")
            return False

    return True

def check_self_signed_certificates(certificates, website_name):
    """
    Checks if any intermediate certificates are self-signed.
    """
    for cert_depth, cert in enumerate(certificates[:-1]):
        if cert.issuer != cert.subject:
            continue

        try:
            public_key = cert.public_key()
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception:
            continue
        else:
            print(f"Certificate for {website_name} at depth {cert_depth} is self-signed.")
            return False

    return True


def validate_trusted_root(certificates, website_name):
    """
    Validates the root certificate's trustworthiness and self-signature.
    """
    trusted_certs = load_trusted_root_certificates()
    root_cert = certificates[-1]

    if root_cert.issuer != root_cert.subject:
        print(f"Invalid chain: Root certificate for {website_name} is not self-signed.")
        return False

    if root_cert not in trusted_certs:
        print(f"Root certificate for {website_name} is not trusted.")
        return False

    try:
        root_public_key = root_cert.public_key()
        root_public_key.verify(
            root_cert.signature,
            root_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            root_cert.signature_hash_algorithm
        )
    except Exception as e:
        print(f"Root certificate for {website_name} failed signature validation: {e}")
        return False

    return True

def check_revocation(certificates, website_name):
    # Not yet implemented, will use OCSP and CRLs for this validation.
    return True

def check_issuer_and_subject(certificates, website_name):
    
    return True

def validate_certificate(certificates, website_name):
    """
    Default validation logic for certificates
    """
    if not validate_certificate_validity(certificates, website_name):
        return False

    if not validate_certificate_signatures(certificates, website_name):
        return False

    if not check_self_signed_certificates(certificates, website_name):
        return False

    if not validate_trusted_root(certificates, website_name):
        return False
    
    if not check_revocation(certificates, website_name):
        return False

    if not check_issuer_and_subject(certificates, website_name):
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
            curve = public_key.curve.name
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
        except Exception as e:
            print(f"Error occured while connecting to {website_name}: {e}")

if __name__ == '__main__':
    main()
