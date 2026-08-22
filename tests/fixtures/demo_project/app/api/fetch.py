import requests
from flask import request

def fetch():
    url = request.args.get("url")
    requests.get(url)
