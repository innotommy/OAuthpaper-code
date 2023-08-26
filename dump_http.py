import json
import os
import sys



def get_headers(headers):
    hdrs = {}

    for name, value in headers:
        hdrs[name.decode('utf-8')] = value.decode('utf-8')

    return hdrs

def get_content(content):
    if content:
        return content.decode('utf-8')
    else:
        return "No-Content"


def response(flow):
    print(json.dumps({
        'request': {
            'timestamp_start': flow.request.timestamp_start,
            'timestamp_end': flow.request.timestamp_end,
            'method': flow.request.method,
            'url': flow.request.url,
            'headers': get_headers(flow.request.headers.fields),
            'content': get_content(flow.request.content)
        },
        'response': {
            'timestamp_start': flow.response.timestamp_start,
            'timestamp_end': flow.response.timestamp_end,
            'status_code': flow.response.status_code,
            'status_text': flow.response.reason,
            'headers': get_headers(flow.response.headers.fields),
            'content': get_content(flow.response.content)
        }
    })+",", file=sys.stdout)
