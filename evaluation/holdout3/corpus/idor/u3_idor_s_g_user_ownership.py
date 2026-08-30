def g_user_doc():
    did = request.args.get("did")
    doc = Document.objects.get(id=did)
    if doc.owner_id != g.user.id:
        raise PermissionError()
    return doc
