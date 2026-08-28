def safe_rand():
    data = request.files["file"].read()
    name = secrets.token_hex(16) + ".dat"
    Path("/data/vault").joinpath(name).write_bytes(data)
