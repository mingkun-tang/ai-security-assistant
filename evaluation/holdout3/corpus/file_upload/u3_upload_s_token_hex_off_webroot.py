def vault_store():
    data = request.files["file"].read()
    name = secrets.token_hex(16) + ".bin"
    Path("/data/vault").joinpath(name).write_bytes(data)
