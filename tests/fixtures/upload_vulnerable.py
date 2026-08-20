from flask import request

def upload():
    uploaded = request.files["file"]
    uploaded.save("static/uploads/" + uploaded.filename)
