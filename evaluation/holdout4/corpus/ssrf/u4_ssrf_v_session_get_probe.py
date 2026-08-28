def probe_peer():
    peer = request.args.get("peer")
    sess = requests.Session()
    return sess.get(peer).content
