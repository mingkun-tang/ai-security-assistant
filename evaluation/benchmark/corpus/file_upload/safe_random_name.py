from flask import request
import uuid

def upload():
    f = request.files["photo"]
    f.save(f"/var/uploads/{uuid.uuid4().hex}.jpg")
