def session_owned_docs():
    return Document.objects.filter(owner_id=session["user_id"])
