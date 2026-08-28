def join_save():
    fn = request.files["asset"].filename
    full = os.path.join("/var/www/html/assets", fn)
    request.files["asset"].save(full)
