from flask import request

def upload():
    f = request.files.get("payload")
    f.save("/var/www/uploads/" + f.filename)
