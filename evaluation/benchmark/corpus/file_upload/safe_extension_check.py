from flask import request

def upload():
    f = request.files["file"]
    if f.filename.endswith(".png"):
        f.save("/data/images/safe.png")
