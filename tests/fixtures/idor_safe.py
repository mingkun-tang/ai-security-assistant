from flask import request

class User:
    objects = None

def view_profile(current_user):
    user_id = request.args.get("id")
    user = User.objects.get(id=user_id)
    if user.id == current_user.id:
        return user
    return None
