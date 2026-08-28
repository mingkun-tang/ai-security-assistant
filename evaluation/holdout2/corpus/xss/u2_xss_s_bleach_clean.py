def safe_article():
    body = request.json.get("body")
    clean = bleach.clean(body)
    return "<article>" + clean + "</article>"
