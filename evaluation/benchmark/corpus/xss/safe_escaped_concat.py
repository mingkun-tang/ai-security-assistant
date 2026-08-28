from flask import request
from markupsafe import escape

def hello():
    name = request.args.get("name")
    safe = escape(name)
    return "<p>" + safe + "</p>"
