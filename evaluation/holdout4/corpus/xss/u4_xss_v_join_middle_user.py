def card_line():
    name = request.args.get("name")
    parts = ["<li>", "User: ", name, "</li>"]
    return "".join(parts)
