from flask import request

def inspect():
    f = request.files["f"]
    data = f.read()
    return {"bytes": len(data)}
