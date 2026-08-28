def partner_only_fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    if host not in {"hooks.acme.io", "events.acme.io"}:
        abort(403)
    return requests.get(raw)
