def welcome_banner():
    who = request.args.get("who", "guest")
    return f"<div class='banner'>Hello {who}</div>"
