def g_owned_documents():
    return Document.objects.filter(owner_id=g.user.id)
