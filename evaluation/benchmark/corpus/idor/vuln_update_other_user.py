from flask import request

class User:
    objects = None

def update_email():
    user_id = request.args.get("user_id")
    email = request.form.get("email")
    user = User.objects.get(id=user_id)
    user.email = email
    user.save()
