def guarded():
    url = request.args.get("url")
    host = urlparse(url).hostname
    if host.startswith("10."):
        raise ValueError("private")
    return requests.get(url)
