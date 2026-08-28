from flask import request

def upload():
    name = request.files["file"].filename
    request.files["file"].save("/tmp/" + name)
