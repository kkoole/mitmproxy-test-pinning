from mitmproxy import ctx, http, proxy
from OpenSSL import crypto
from cryptography import x509


class CustomCertificateAddon:
    def __init__(self):
        self.hostname = "sha256.badssl.com"  # Specify the hostname for which you want to replace the certificate

    def load(self, loader):
        loader.add_option(
            name="custom_certificate_hostname",
            typespec=str,
            default=self.hostname,
            help="Specify the hostname to intercept SSL connections and replace the certificate"
        )

    def configure(self, updated):
        self.hostname = ctx.options.custom_certificate_hostname

    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.pretty_host == self.hostname and flow.request.scheme == "https":
            self.replace_certificate(flow)

        ctx.log('DEBUG: "{}"'.format(flow.client_conn.mitmcert))
        ctx.log('DEBUG: mitmproxy cert "{}"'.format(flow.client_conn.mitmcert))
        ctx.log('DEBUG: mitmproxy cert issuer "{}"'.format(flow.client_conn.mitmcert.issuer))
        ctx.log('DEBUG: mitmproxy cert subject "{}"'.format(flow.client_conn.mitmcert.subject))

    def replace_certificate(self, flow: http.HTTPFlow):
        cert = crypto.X509()  # Create a new X.509 certificate

        # Configure the certificate with desired details
        cert.get_subject().CN = self.hostname
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000)
        cert.set_issuer(cert.get_subject())
        #cert.set_pubkey(cert.get_pubkey())
        #cert.sign(cert.get_pubkey(), "sha256")

        #Generate a private key
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)

        # Sign the certificate with the private key
        cert.set_pubkey(pkey)
        cert.sign(pkey, "sha256")
        
        # Convert the certificate to PEM format
        pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

        # Replace the server's certificate in the SSL/TLS handshake
        #flow.server_conn.certificate_list = [pem_cert]

        # convert to cryptography Certificate object
        mitmproxy_cert = x509.load_pem_x509_certificate(pem_cert)

        flow.client_conn.mitmcert = mitmproxy_cert
        #flow.server_conn.ssl_established = True
     

addons = [
    CustomCertificateAddon()
]

if __name__ == "__main__":
    # Use mitmproxy's built-in command line launcher
    # to start the proxy with the addon
    config = proxy.ProxyConfig(addons=addons)
    server = proxy.ProxyServer(config)
    m = proxy.ProxyMaster(server)
    m.run()

