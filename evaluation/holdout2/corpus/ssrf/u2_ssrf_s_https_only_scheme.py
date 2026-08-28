def safe_https():
    u = request.args.get("u")
    if not u.startswith("https://"):
        raise ValueError("https only")
    return requests.get(u)
