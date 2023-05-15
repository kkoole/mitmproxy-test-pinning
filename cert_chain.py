from mitmproxy import ctx
from mitmproxy import flow

def cert_chain(flow):
    if flow.client_conn.tls_established:
        ctx.log.info('Server cert chain "{}"'.format(flow.server_conn.cert_chain))
        ctx.log.info('Client cert chain "{}"'.format(flow.client_conn.cert_chain))
