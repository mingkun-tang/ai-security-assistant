from flask import request

def upload():
    doc = request.files["doc"]
    doc.save("public/docs/" + doc.filename)
