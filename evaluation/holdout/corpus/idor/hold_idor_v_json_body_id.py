from flask import request

class Document:
    objects = None

def open_doc():
    payload = request.get_json()
    doc_id = payload.get("document_id")
    return Document.objects.get(id=doc_id)
