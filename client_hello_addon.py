from mitmproxy import ctx


def request(flow):
    if flow.client_conn and flow.client_conn.tls_established:
        tls_client_certificate_list = flow.client_conn.certificate_list
        if tls_client_certificate_list:
            ctx.log('Certificate list "{}"'.format(tls_client_certificate_list))
        tls_client_hello_sni = flow.client_conn.sni
        if tls_client_hello_sni:
            ctx.log('SNI data "{}"'.format(tls_client_hello_sni))
        tls_client_cipher = flow.client_conn.cipher
        if tls_client_cipher:
            ctx.log('Cipher "{}"'.format(tls_client_cipher))
        tls_client_cipher_list = flow.client_conn.cipher_list
        if tls_client_cipher_list:
            ctx.log('Cipher list "{}"'.format(tls_client_cipher_list))

    if flow.server_conn and flow.server_conn.tls_established:
        tls_server_certificate_list = flow.server_conn.certificate_list
        if tls_server_certificate_list:
            ctx.log('Certificate list "{}"'.format(tls_server_certificate_list))
        

addons = [
    request
]
