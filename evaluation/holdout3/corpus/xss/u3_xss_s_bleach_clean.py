def comment():
    text = request.form.get("text")
    cleaned = bleach.clean(text)
    return "<div>" + cleaned + "</div>"
