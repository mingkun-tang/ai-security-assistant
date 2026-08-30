def inspect_url():
    raw = request.args.get("raw")
    parsed = urlparse(raw)
    return {"scheme": parsed.scheme, "path": parsed.path}
