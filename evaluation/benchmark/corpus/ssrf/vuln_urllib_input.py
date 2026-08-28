import urllib.request
from flask import request

def fetch():
    url = request.args.get("url")
    urllib.request.urlopen(url)
