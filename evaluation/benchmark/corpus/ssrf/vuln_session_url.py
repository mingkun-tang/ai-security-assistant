import requests
from flask import request

def fetch(session):
    url = request.args.get("redirect")
    session.get(url)
