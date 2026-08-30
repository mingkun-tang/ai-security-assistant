def require_https_scheme():
    u = request.args.get("u")
    if urlparse(u).scheme != "https":
        abort(400)
    return requests.get(u)
