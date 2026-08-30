def sanitized_hex_save():
    raw = request.files["f"].filename
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "", raw)
    if not cleaned:
        raise ValueError("name")
    request.files["f"].save("/data/files/" + secrets.token_hex(10) + ".dat")
