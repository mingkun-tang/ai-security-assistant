def block_rfc1918_fetch():
    url = request.args.get("url")
    host = urlparse(url).hostname
    if host.startswith("192.168."):
        raise ValueError("private")
    return requests.get(url)
