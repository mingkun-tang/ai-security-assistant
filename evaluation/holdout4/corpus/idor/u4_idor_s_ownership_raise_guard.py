class CaseFile:
    objects = None

def open_casefile():
    cid = request.args.get("cid")
    item = CaseFile.objects.get(pk=cid)
    if item.user_id != g.user.id:
        raise PermissionError("not owner")
    return item
