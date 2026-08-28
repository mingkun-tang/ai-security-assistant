def store_path():
    fn = request.files["f"].filename
    Path("/var/www/uploads").joinpath(fn).write_bytes(request.files["f"].read())
