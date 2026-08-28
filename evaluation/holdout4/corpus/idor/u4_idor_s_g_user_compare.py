def g_user_owned():
    rid = request.args.get("rid")
    row = Note.objects.get(id=rid)
    if row.owner_id != g.user.id:
        abort(403)
    return row
