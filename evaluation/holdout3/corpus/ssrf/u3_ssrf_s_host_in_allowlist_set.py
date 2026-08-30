def set_allow_fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    allow = {"img.cdn.com", "static.cdn.com"}
    if host in allow:
        return requests.get(raw)
    raise ValueError("blocked")
