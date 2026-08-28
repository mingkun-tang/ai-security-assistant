def safe_get():
    rid = request.args.get("rid")
    row = Record.objects.get(id=rid)
    if row.user_id != g.user.id:
        raise PermissionError()
    return row
