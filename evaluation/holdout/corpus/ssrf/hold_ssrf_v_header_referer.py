import requests
from flask import request

def preview():
    referer = request.headers.get("Referer")
    requests.get(referer)
