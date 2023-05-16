from mitmproxy import ctx, http


class CertificatePinningAddon:
    def __init__(self):
        self.expected_attributes = {
            # Define the expected X.509 attributes for pinning validation
            # Adjust these values according to the application's pinning logic
            "issuer": "Expected Issuer",
            "subject": "Expected Subject",
            "expiry": "Expected Expiry Date",
            # Add more expected attributes as needed
        }

    def http_connect(self, flow: http.HTTPFlow):
        if flow.metadata.get("tls_established"):
            certificate = flow.server_conn.connection.server_tls._ctx.get_cert()
            x509 = certificate.to_cryptography()

            if self.validate_pinning(x509):
                ctx.log.info("Certificate pinning is valid")
            else:
                ctx.log.error("Certificate pinning validation failed")

    def validate_pinning(self, x509):
        for attr, expected_value in self.expected_attributes.items():
            attr_value = getattr(x509.subject, attr)
            if attr_value != expected_value:
                return False

        # Additional checks for the certificate chain can be added here

        return True


addons = [
    CertificatePinningAddon()
]

