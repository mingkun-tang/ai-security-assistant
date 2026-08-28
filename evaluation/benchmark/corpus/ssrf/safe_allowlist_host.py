import requests
from flask import abort, request
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.hostname not in ALLOWED:
        abort(400)
    requests.get(url)
