def link():
    dest = request.args.get("dest")
    return "<a href='" + dest + "'>go</a>"
