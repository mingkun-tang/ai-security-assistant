def greet_user():
    who = request.args.get("who", "guest")
    return f"<p>Hello {escape(who)}</p>"
