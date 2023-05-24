from mitmproxy import ctx
from mitmproxy import http


def response(flow):
    if flow.response and flow.response.content:
        response = flow.response.content
        ctx.log('Content of the response "{}"'.format(response))

addons = [
    response
]

