def join_write():
    fn = request.files["asset"].filename
    Path("/var/www/html/assets").joinpath(fn).write_bytes(request.files["asset"].read())
