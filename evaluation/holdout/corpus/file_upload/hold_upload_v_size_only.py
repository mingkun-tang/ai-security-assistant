from flask import request

def upload():
    blob = request.files["blob"]
    if blob.content_length and blob.content_length > 5000000:
        return "too large", 400
    blob.save("static/media/" + blob.filename)
