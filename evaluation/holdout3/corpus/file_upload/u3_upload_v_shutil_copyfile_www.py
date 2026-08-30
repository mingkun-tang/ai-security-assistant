def copyfile_www():
    name = request.files["src"].filename
    tmp = "/tmp/" + name
    request.files["src"].save(tmp)
    shutil.copyfile(tmp, "/var/www/html/" + name)
