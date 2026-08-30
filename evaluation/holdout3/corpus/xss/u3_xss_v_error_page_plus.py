def fail():
    reason = request.args.get("reason")
    return "<h1>Error</h1><p>" + reason + "</p>"
