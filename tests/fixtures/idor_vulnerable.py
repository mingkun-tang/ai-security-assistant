from flask import request

class User:
    objects = None

def view_profile():
    user_id = request.args.get("id")
    user = User.objects.get(id=user_id)
    return user
