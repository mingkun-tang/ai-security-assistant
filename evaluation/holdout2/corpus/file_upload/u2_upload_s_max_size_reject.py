def capped():
    f = request.files["f"]
    if len(f.read()) > 1000000:
        raise ValueError("too big")
    f.seek(0)
    f.save("/data/capped/" + secrets.token_hex(8) + ".bin")
