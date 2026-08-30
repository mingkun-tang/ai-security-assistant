def label():
    raw = request.args.get("label")
    mid = raw
    final = mid
    return "<span>" + final + "</span>"
