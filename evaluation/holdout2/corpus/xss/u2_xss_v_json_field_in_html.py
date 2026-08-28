def preview():
    body = request.json.get("body")
    return "<article>" + body + "</article>"
