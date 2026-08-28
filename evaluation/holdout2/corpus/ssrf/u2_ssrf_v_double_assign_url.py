def mirror():
    u = request.args.get("u")
    w = u
    return requests.get(w).content
