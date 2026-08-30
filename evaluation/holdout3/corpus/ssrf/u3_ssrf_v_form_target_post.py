def submit_remote():
    target = request.form.get("target")
    return requests.post(target, data={"event": "ping"})
