def safe_delete_doc():
    doc_id = request.form.get("doc_id")
    doc = Document.objects.get(id=doc_id)
    if doc.owner_id != session["user_id"]:
        raise PermissionError()
    doc.delete()
