def fail():
    msg = request.args.get("msg")
    return "<p class=err>" + msg + "</p>"
