from flask import request

def upload():
    up = request.files["script"]
    up.save("uploads/" + up.filename)
