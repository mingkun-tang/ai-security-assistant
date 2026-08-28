from flask import request

class User:
    objects = None

def update_email(current_user):
    user_id = request.args.get("user_id")
    user = User.objects.get(id=user_id)
    if user.id != current_user.id:
        return None
    user.email = request.form.get("email")
    user.save()
