from flask import request

class Profile:
    objects = None

def show():
    uid = request.form.get("user_id")
    return Profile.objects.get(id=uid)
