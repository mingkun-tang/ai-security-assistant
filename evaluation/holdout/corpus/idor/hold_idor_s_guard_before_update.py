from flask import abort, request
from flask_login import current_user

class Settings:
    objects = None

def update():
    settings_id = request.form.get("id")
    row = Settings.objects.get(id=settings_id)
    if row.user_id != current_user.id:
        abort(403)
    row.theme = request.form.get("theme")
    row.save()
