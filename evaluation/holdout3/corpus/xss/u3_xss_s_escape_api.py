def chip():
    label = request.args.get("label")
    return "<span>" + escape(label) + "</span>"
