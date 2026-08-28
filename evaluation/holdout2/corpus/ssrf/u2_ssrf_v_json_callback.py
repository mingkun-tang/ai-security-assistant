def callback():
    cb = request.json.get("callback")
    return urllib.request.urlopen(cb).read()
