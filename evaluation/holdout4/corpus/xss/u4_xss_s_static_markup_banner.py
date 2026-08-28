def site_banner():
    _ = request.args.get("campaign")
    return Markup("<div class='banner'>Welcome back</div>")
