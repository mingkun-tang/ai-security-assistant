from flask import request

class User:
    objects = None

def my_profile(current_user):
    return User.objects.get(id=current_user.id)
