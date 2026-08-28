from flask import request

def upload():
    data = request.files["doc"]
    data.save(data.filename)
