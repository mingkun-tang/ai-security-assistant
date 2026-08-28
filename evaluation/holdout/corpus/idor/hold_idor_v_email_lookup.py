from flask import request

class User:
    objects = None

def find_user():
    email = request.args.get("email")
    return User.objects.filter(email=email).first()
