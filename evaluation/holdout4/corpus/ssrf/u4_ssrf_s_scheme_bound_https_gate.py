def require_bound_https():
    u = request.args.get("u")
    parsed = urlparse(u)
    if parsed.scheme != "https":
        abort(400)
    return requests.get(u)
