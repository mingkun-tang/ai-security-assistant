def greet():
    who = request.args.get("who")
    return Markup("<h2>Hello {}</h2>".format(who))
