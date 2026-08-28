def parse_only():
    raw = request.args.get("raw")
    return urlparse(raw).path
