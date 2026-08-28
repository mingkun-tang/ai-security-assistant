def safe_greet():
    who = request.args.get("who")
    return "<h2>" + escape(who) + "</h2>"
