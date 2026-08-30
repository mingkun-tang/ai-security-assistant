import html

def hello():
    name = request.args.get("name")
    safe = html.escape(name)
    return f"<p>Hello {safe}</p>"
