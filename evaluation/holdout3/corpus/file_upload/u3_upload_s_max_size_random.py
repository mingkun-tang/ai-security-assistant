def size_capped():
    f = request.files["f"]
    raw = f.read()
    if len(raw) > 500000:
        raise ValueError("too big")
    Path("/data/capped/" + secrets.token_hex(8) + ".bin").write_bytes(raw)
