def safe_fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    if host not in {"api.example.com", "cdn.example.com"}:
        raise ValueError("host")
    return requests.get(raw)
