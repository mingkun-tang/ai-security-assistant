from flask import request

class Profile:
    objects = None

def show():
    pid = request.args.get("profile_id")
    return Profile.objects.get(id=pid)
