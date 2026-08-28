import requests
from flask import request

def fetch():
    path = request.args.get("path")
    requests.get(f"https://internal.service/{path}")
