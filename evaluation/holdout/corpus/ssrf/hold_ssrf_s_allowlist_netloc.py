import requests
from flask import abort, request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"cdn.example.com", "api.example.com"}

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(403)
    requests.get(url)
