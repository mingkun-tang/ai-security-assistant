def pull_callback():
    callback = request.args.get("callback")
    return requests.get(callback).text
