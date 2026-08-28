def reject_exec():
    fn = request.files["f"].filename
    if fn.endswith(".py") or fn.endswith(".sh"):
        raise ValueError("blocked")
    request.files["f"].save("/data/store/" + fn)
