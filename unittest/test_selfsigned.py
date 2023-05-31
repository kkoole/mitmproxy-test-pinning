#!/usr/bin/env python3
"""
Python script used to perform testing of certificate pinning implementations
using self-signed certificate, part of mitmproxy-test-pinning.
Authors: Julia Kulacz, Kaj Koole
"""

import os, sys
from gen_cert import GenerateCertificate
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def get_attribute_value(attributes, oid):
    attribute = attributes.get_attributes_for_oid(oid)
    if attribute:
        return attribute[0].value
    return None


def print_certificate_attributes(cert_file):
    # Load the certificate from the file
    with open(cert_file, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read())

    # Print various attributes of the certificate
    print("Subject:")
    print("  Common Name (CN):", get_attribute_value(cert.subject, x509.NameOID.COMMON_NAME))
    print("  Organization (O):", get_attribute_value(cert.subject, x509.NameOID.ORGANIZATION_NAME))
    print("  Country (C):", get_attribute_value(cert.subject, x509.NameOID.COUNTRY_NAME))
    print("  State or Province (ST):", get_attribute_value(cert.subject, x509.NameOID.STATE_OR_PROVINCE_NAME))
    print("  Locality (L):", get_attribute_value(cert.subject, x509.NameOID.LOCALITY_NAME))
    print("Issuer:")
    print("  Common Name (CN):", get_attribute_value(cert.issuer, x509.NameOID.COMMON_NAME))
    print("  Organization (O):", get_attribute_value(cert.issuer, x509.NameOID.ORGANIZATION_NAME))
    print("  Country (C):", get_attribute_value(cert.issuer, x509.NameOID.COUNTRY_NAME))
    print("  State or Province (ST):", get_attribute_value(cert.issuer, x509.NameOID.STATE_OR_PROVINCE_NAME))
    print("  Locality (L):", get_attribute_value(cert.issuer, x509.NameOID.LOCALITY_NAME))
    print("Valid From:", cert.not_valid_before)
    print("Valid Until:", cert.not_valid_after)


def main(entry="*.badssl.com"):
    # Generate certificate
    gencert = GenerateCertificate()
    gencert.gen_selfsigned()

    # Load certificates
    certificates = []
    for i in os.listdir():
        if ".pem" in i and "cert" in i:
            certificates.append(i.strip())

    # Launch mitmdump using certificates
    for cert in certificates:
        print("Using certificate file: %s"%(cert))

        # Print various attributes of the certificate
        print_certificate_attributes(cert) 

        # Launch mitmdump using specific certificate
        print("Start mitmdump...")
        try:
            print(os.system("./mitmdump --certs %s=%s"%(entry.strip(), cert)))
        except KeyboardInterrupt:
            continue
    return


if __name__ == '__main__':
    hostlist = open(sys.argv[1], 'r').readlines()
    for entry in hostlist:
        main(entry)
