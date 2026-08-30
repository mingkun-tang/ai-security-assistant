import html

def box():
    user = request.args.get("user")
    return Markup(html.escape(user))
