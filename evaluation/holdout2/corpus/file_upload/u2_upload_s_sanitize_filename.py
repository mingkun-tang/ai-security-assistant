def clean_name():
    raw = request.files["f"].filename
    safe = re.sub(r"[^a-zA-Z0-9._-]", "", raw)
    request.files["f"].save("/data/files/" + safe)
