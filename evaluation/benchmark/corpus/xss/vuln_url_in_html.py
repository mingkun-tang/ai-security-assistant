from flask import request

def link():
    target = request.args.get("url")
    return "<a href='" + target + "'>click</a>"
