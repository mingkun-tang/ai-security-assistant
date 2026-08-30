def allow_image_jpg():
    fn = request.files["img"].filename
    if not fn.lower().endswith(".jpg"):
        raise ValueError("jpg only")
    request.files["img"].save("/data/photos/" + secrets.token_hex(8) + ".jpg")
