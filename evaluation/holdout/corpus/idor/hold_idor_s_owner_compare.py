from flask import abort, request
from flask_login import current_user

class Note:
    objects = None

def read():
    note_id = request.args.get("id")
    note = Note.objects.get(id=note_id)
    if note.owner_id != current_user.id:
        abort(403)
    return note
