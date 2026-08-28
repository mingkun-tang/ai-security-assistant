import requests
from flask import abort, request
from urllib.parse import urlparse

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.scheme == "http":
        abort(400)
    requests.get(url)
