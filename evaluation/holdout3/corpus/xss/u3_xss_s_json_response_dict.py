def payload():
    q = request.args.get("q")
    return {"ok": True, "q": q}, 200, {"Content-Type": "application/json"}
