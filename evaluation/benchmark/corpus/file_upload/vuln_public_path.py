from flask import request

def upload():
    blob = request.files["image"]
    blob.save("public/" + blob.filename)
