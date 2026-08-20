from flask import request

def upload():
    uploaded = request.files.get("avatar")
    if uploaded.filename.endswith(".jpg"):
        uploaded.save("/var/uploads/photo.jpg")
