def allowlisted_fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    if host not in {"hooks.partner.com", "cdn.partner.com"}:
        raise ValueError("denied")
    return requests.get(raw)
