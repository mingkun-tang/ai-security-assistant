def join_web_save():
    fn = request.files["asset"].filename
    path = os.path.join("/var/www/html/files", fn)
    request.files["asset"].save(path)
