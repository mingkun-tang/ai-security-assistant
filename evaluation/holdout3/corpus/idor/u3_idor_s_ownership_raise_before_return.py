def guarded_record():
    rid = request.args.get("rid")
    row = Record.objects.get(id=rid)
    if row.owner_id != session["user_id"]:
        raise PermissionError()
    return row
