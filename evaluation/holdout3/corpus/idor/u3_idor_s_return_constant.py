def ping_status():
    ignored = request.args.get("id")
    return {"status": "ok"}
