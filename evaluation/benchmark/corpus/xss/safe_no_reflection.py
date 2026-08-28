from flask import request

def hello():
    name = request.args.get("name")
    return {"greeting": "hello", "ignored": name is not None}
