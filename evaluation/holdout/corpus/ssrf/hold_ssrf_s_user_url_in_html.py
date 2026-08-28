from flask import request

def page():
    href = request.args.get("href")
    return "<a href='" + href + "'>external</a>"
