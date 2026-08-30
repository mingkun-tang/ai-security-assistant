def path_token_write():
    data = request.files["f"].read()
    Path("/data/objects/" + secrets.token_hex(16)).write_bytes(data)
