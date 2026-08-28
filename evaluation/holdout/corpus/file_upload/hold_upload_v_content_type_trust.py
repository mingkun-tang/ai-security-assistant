from flask import request

def upload():
    pic = request.files["pic"]
    if pic.mimetype == "image/png":
        pic.save("/srv/app/uploads/" + pic.filename)
