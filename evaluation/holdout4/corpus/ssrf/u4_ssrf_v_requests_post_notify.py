def notify_remote():
    notify = request.args.get("notify")
    return requests.post(notify, json={"event": "ready"})
