def badge():
    label = request.args.get("label")
    inner = "<span>" + label + "</span>"
    return "<div>" + inner + "</div>"
