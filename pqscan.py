import ssl
import socket
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec


def scan(domain):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                tls = ssock.version()
                cipher = ssock.cipher()[0]
                cert_der = ssock.getpeercert(binary_form=True)

                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                pubkey = cert.public_key()

                algo = "Unknown"
                key_size = "Unknown"

                if isinstance(pubkey, rsa.RSAPublicKey):
                    algo = "RSA"
                    key_size = pubkey.key_size

                elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                    algo = "ECC"
                    key_size = pubkey.key_size

                quantum_risk = "HIGH"
                current_risk = "LOW"

                fix = "Upgrade to post-quantum or hybrid TLS."

                print("\n==============================")
                print(" POST-QUANTUM SECURITY REPORT ")
                print("==============================\n")

                print(f"Domain          : {domain}")
                print(f"TLS Version     : {tls}")
                print(f"Cipher          : {cipher}")
                print(f"Algorithm       : {algo}")
                print(f"Key Size        : {key_size}")

                print(f"\nCurrent Risk    : {current_risk}")
                print(f"Quantum Risk    : {quantum_risk}")

                print(f"\nSuggested Fix:")
                print(f"-> {fix}")

                print("\nSTATUS:")
                print("⚠️  Vulnerable in future quantum era")

    except Exception as e:
        print(f"\nError scanning {domain}")
        print(e)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python pqscan.py <domain>")
        sys.exit()

    domain = sys.argv[1]
    scan(domain)
