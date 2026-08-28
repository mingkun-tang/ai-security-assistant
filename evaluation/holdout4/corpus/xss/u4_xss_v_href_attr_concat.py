def next_link():
    dest = request.args.get("next")
    return '<a href="' + dest + '">Continue</a>'
