def fetch_document():
    doc_id = request.json.get("document_id")
    return Document.objects.get(id=doc_id)
