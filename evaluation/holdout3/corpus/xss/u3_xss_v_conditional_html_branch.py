def status():
    mode = request.args.get("mode")
    if mode == "ok":
        return "<p>ok</p>"
    detail = request.args.get("detail")
    return "<p>error: " + detail + "</p>"
