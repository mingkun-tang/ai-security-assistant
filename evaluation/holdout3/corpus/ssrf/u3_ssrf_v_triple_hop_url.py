def hop_fetch():
    a = request.args.get("a")
    b = a
    c = b
    return requests.get(c).text
