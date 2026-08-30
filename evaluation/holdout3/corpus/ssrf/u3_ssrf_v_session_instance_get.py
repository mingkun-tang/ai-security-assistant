def session_probe():
    addr = request.args.get("addr")
    client = requests.Session()
    return client.get(addr).content
