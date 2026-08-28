from flask import request

def button():
    action = request.args.get("action")
    return "<button onclick='" + action + "'>Run</button>"
