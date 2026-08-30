def no_private_ten():
    url = request.args.get("url")
    host = urlparse(url).hostname or ""
    if host.startswith("10."):
        raise ValueError("private")
    return requests.get(url)
