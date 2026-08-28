def asset():
    base = request.args.get("base")
    path = request.args.get("path")
    url = os.path.join(base, path)
    return requests.get(url)
