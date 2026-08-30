def uuid_blob():
    data = request.files["blob"].read()
    sub = str(uuid.uuid4())
    Path("/data/blobs/" + sub + "/payload.bin").write_bytes(data)
