def tmp_public():
    name = request.files["img"].filename
    request.files["img"].save("/var/www/html/tmp/" + name)
