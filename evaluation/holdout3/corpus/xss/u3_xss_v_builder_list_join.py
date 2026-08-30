def card():
    title = request.args.get("title")
    parts = ["<article><h3>", title, "</h3></article>"]
    return "".join(parts)
