def titled_panel():
    title = request.args.get("title")
    return Markup("<h2>%s</h2>") % title
