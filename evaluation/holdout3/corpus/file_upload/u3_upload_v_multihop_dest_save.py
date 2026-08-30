def hop_dest_save():
    a = request.files["file"].filename
    b = a
    dest = "/var/www/html/drop/" + b
    request.files["file"].save(dest)
