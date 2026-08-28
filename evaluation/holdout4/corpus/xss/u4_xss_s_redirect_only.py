def go_home():
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/"):
        nxt = "/"
    return redirect(nxt)
