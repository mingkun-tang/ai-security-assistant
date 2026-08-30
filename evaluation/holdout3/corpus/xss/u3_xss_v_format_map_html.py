def greet():
    name = request.args.get("name")
    return "<h1>Hi {name}</h1>".format_map({"name": name})
