def tmp_under_html():
    name = request.files["img"].filename
    request.files["img"].save("/var/www/html/tmp/" + name)
