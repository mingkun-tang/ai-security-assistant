def chips():
    items = request.args.get("items")
    parts = ["<ul>", items, "</ul>"]
    return "".join(parts)
