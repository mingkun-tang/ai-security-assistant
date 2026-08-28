import requests
from flask import request

def fetch():
    incoming = request.args.get("src")
    target = incoming
    destination = target
    requests.get(destination)
