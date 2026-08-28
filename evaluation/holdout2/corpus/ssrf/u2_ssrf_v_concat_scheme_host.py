def open_link():
    scheme = request.args.get("scheme")
    host = request.args.get("host")
    return requests.get(scheme + "://" + host)
