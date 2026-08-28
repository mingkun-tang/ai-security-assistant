import requests
from flask import request

def fetch():
    host = request.args.get("host")
    requests.get("http://" + host + "/api")
