from flask import request

def upload():
    f = request.files.get("file")
    return {"size": len(f.read()) if f else 0}
