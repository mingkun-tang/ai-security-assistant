from flask import abort, request

def upload():
    f = request.files["f"]
    if f.filename.endswith(".php"):
        abort(400)
    f.save("/var/storage/blob.bin")
