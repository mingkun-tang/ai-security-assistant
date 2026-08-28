def my_docs():
    owner = session["user_id"]
    return Document.objects.filter(owner_id=owner)
