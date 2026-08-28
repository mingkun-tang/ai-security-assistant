def record_click():
    target = request.args.get("target")
    metrics.incr("click", tags={"target": target})
    return ("", 204)
