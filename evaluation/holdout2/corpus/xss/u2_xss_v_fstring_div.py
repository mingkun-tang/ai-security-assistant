def card():
    title = request.form.get("title")
    return f"<div class=card>{title}</div>"
