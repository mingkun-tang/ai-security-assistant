import html
from flask import request

def note():
    body = request.args.get("body")
    escaped = html.escape(body)
    return "<article>" + escaped + "</article>"
