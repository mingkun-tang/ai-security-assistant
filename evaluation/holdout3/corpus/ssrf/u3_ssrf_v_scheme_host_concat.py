def build_fetch():
    proto = request.args.get("proto")
    node = request.args.get("node")
    return requests.get(proto + "://" + node + "/info")
