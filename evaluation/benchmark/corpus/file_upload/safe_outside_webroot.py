from flask import request

def upload():
    f = request.files["doc"]
    f.save("/var/secure_storage/document.pdf")
