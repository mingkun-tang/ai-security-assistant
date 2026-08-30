def get_then_check():
    rid = request.args.get("rid")
    row = Note.objects.get(id=rid)
    if row.owner_id != session["user_id"]:
        raise PermissionError()
    return row
