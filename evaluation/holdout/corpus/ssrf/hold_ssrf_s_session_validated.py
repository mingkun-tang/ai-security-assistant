from flask import abort, request
from urllib.parse import urlparse

ALLOWED = {"hooks.example.com"}

def pull(session):
    url = request.args.get("hook")
    parsed = urlparse(url or "")
    if parsed.hostname not in ALLOWED:
        abort(400)
    session.get(url)
