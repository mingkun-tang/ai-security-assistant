def note():
    text = request.form.get("text")
    return "<em>%s</em>" % text
