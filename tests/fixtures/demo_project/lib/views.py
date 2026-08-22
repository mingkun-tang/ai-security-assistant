from flask import render_template, request

def hello():
    name = request.args.get("name")
    return render_template("hello.html", name=name)
