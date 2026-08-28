import os
from flask import request

def upload():
    up = request.files["file"]
    path = os.path.join("/var/www/uploads", up.filename)
    up.save(path)
