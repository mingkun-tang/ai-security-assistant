import httpx
from flask import request

def proxy():
    endpoint = request.args.get("endpoint")
    httpx.get(endpoint)
