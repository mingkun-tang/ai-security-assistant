def banner():
    msg = request.args.get("msg")
    return Markup("<div class='banner'>%s</div>" % msg)
