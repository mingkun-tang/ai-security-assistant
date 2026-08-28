def safe_card():
    title = request.form.get("title")
    return f"<div>{escape(title)}</div>"
