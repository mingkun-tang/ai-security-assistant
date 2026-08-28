from flask import request

def stash():
    f = request.files.get("f")
    f.save("/tmp/" + f.filename)
