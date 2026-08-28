def https_prefix_gate():
    link = request.args.get("link")
    if not link.startswith("https://"):
        raise ValueError("https required")
    return requests.get(link)
