import html

def safe_greet():
    name = request.args.get("name")
    return "<p>Hi " + html.escape(name) + "</p>"
