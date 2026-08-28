from flask import request

def greet():
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"
