def chain_save():
    a = request.files["file"].filename
    b = a
    dest = "/var/www/html/" + b
    request.files["file"].save(dest)
