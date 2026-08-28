from flask import request

def comment():
    text = request.args.get("comment")
    return "<div>" + text + "</div>"
