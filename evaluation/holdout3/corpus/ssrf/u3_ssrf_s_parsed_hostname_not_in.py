def deny_unknown_host():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    allowed = {"api.trusted.com"}
    if host not in allowed:
        raise PermissionError("host")
    return requests.get(raw)
