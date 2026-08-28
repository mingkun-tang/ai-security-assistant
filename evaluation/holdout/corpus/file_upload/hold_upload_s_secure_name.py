from flask import request
from werkzeug.utils import secure_filename

def upload():
    f = request.files["f"]
    name = secure_filename(f.filename)
    f.save("/var/data/" + name)
