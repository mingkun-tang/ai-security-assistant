def uuid_dir():
    data = request.files["blob"].read()
    sub = str(uuid.uuid4())
    Path("/data/blobs/" + sub).write_bytes(data)
