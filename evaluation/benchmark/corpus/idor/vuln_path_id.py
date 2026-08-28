from flask import request

class Document:
    objects = None

def open_doc():
    doc_id = request.view_args.get("doc_id")
    return Document.objects.get(id=doc_id)
