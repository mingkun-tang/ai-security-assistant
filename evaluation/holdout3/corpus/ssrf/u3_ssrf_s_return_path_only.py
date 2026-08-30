def path_of():
    raw = request.args.get("raw")
    return urlparse(raw).path
