from flask import abort, request

def upload():
    img = request.files["img"]
    if not img.filename.endswith(".png"):
        abort(400)
    img.save("/data/images/archive.png")
