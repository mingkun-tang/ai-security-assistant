from flask import request, abort

def upload():
    f = request.files["file"]
    if f.filename.endswith(".exe"):
        abort(400)
    f.save("/var/uploads/image.jpg")
