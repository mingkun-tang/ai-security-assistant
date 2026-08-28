def concat_fetch():
    base = request.args.get("base")
    return requests.get(base + "/v1/check")
