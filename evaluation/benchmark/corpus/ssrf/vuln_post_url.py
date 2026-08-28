import requests
from flask import request

def proxy():
    target = request.form.get("callback")
    requests.post(target, data={"ok": True})
