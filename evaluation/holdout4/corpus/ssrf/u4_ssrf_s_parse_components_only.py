def describe_url():
    raw = request.args.get("raw")
    parsed = urlparse(raw)
    return {"netloc": parsed.netloc, "path": parsed.path}
