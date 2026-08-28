def drop_media():
    fn = request.files["f"].filename
    Path("/var/www/html/media/" + fn).write_bytes(request.files["f"].read())
