from flask import request

def badge():
    label = request.args.get("label")
    return "<span class='badge'>" + label + "</span>"
