def fire_hook():
    hook = request.json.get("callback_hook")
    return urllib.request.urlopen(hook).read()
