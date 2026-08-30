def join_fetch():
    root = request.args.get("root")
    leaf = request.args.get("leaf")
    built = os.path.join(root, leaf)
    return requests.get(built)
