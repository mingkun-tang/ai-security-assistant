import requests
from flask import abort, request
from urllib.parse import urlparse

def fetch():
    url = request.form.get("callback")
    parsed = urlparse(url or "")
    if parsed.scheme != "https":
        abort(400)
    requests.get(url)
