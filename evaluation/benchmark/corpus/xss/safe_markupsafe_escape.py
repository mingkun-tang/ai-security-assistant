from flask import render_template, request
from markupsafe import escape

def hello():
    name = request.args.get("name")
    return render_template("hello.html", name=escape(name))
