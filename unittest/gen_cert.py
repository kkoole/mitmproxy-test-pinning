"""
Python module used to generate certificates for mitmproxy-test-pinning.
Authors: Julia Kulacz, Kaj Koole
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


class GenerateCertificate():
    def __init__(self, hostname="example.com"):
        self.hostname = hostname  # Specify the hostname for which you want to replace the certificate

    def gen_selfsigned(self, filename="./cert_selfsigned.pem"):
        # Generate a new private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create a subject for the certificate
        subject = issuer = x509.Name([
            #x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            #x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            #x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            #x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"%s" % self.hostname)
        ])

        # Create a certificate builder
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        # Sign the certificate with the private key
        cert_builder = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )

        # Convert the certificate to PEM format
        pem_certificate = cert_builder.public_bytes(encoding=serialization.Encoding.PEM)

        # Convert the private key to PEM format
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Output certificate and key in combined file (necessary for mitmdump)
        with open(filename, 'wb') as f:
            f.write(pem_certificate)
            f.write(pem_private_key)
        return pem_certificate, pem_private_key

    
    def gen_casigned(self, ca_filename="./ca_cert.pem", filename="./cert_casigned.pem"):
        # Load the CA certificate from a file
        with open(ca_filename, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Generate a certificate signing request (CSR)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        csr_subject = x509.Name([
            #x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            #x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
            #x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
            #x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'My Organization'),
            x509.NameAttribute(NameOID.COMMON_NAME, u"%s" % self.hostname)
        ])

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            csr_subject
        ).sign(key, hashes.SHA256())

        # Generate a signed certificate using the CA certificate
        cert_builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            dates.datetime.datetime.utcnow()
        ).not_valid_after(
            dates.datetime.datetime.utcnow() + dates.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(ca_cert.private_key, hashes.SHA256())

        # Convert the certificate to PEM format
        pem_certificate = cert_builder.public_bytes(encoding=serialization.Encoding.PEM)

        # Convert the private key to PEM format
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Save the signed certificate to a file
        with open(filename, 'wb') as f:
            f.write(cert_builder.public_bytes(serialization.Encoding.PEM))

