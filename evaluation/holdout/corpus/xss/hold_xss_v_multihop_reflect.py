from flask import request

def greet():
    raw = request.args.get("q")
    message = raw
    label = message
    return "<p>" + label + "</p>"
