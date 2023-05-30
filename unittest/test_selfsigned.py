#!/usr/bin/env python3

import os, sys
from create_cert import GenerateCertificate

def main(entry="*.badssl.com"):
    suite = GenerateCertificate()

    # execute test cases
    certificates = []
    # TODO: return path
    suite.gen_selfsigned()
    suite.gen_casigned()
    for i in os.listdir():
        if ".pem" in i and "cert" in i:
            certificates.append(i.strip())

    print(certificates)
    for cert in certificates:
        try:
            workdir = os.getcwd()
            print(entry, cert, workdir)
            print(os.system("./mitmdump --certs %s=%s"%(entry.strip(), cert)))
        except KeyboardInterrupt:
            continue
    return

if __name__ == '__main__':
    hostlist = open(sys.argv[1], 'r').readlines()
    for entry in hostlist:
        main(entry)
