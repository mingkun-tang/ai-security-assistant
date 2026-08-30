def reject_scripts():
    fn = request.files["f"].filename
    if fn.endswith(".py") or fn.endswith(".sh"):
        raise ValueError("blocked")
    request.files["f"].save("/data/inbox/" + secrets.token_hex(12) + ".bin")
