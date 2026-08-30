def https_only_pull():
    u = request.args.get("u")
    if not u.startswith("https://"):
        abort(400)
    return requests.get(u)
