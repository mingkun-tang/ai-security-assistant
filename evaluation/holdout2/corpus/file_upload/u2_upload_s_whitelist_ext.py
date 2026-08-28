def images_only():
    fn = request.files["img"].filename
    ext = os.path.splitext(fn)[1].lower()
    if ext not in {".png", ".jpg"}:
        raise ValueError("type")
    request.files["img"].save("/data/images/" + secrets.token_hex(8) + ext)
