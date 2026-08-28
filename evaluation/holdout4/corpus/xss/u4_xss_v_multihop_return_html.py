def profile_label():
    raw = request.args.get("label")
    mid = raw
    label = mid.strip()
    html = "<span class='label'>" + label + "</span>"
    return html
