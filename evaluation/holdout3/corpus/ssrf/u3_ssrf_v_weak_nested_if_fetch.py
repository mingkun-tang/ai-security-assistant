def maybe_fetch():
    url = request.args.get("url")
    if url:
        if "://" in url:
            return requests.get(url).content
    return b""
