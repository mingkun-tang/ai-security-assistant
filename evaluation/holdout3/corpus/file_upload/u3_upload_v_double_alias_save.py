def alias_chain_save():
    first = request.files["file"].filename
    second = first
    dest = "/var/www/html/inbox/" + second
    request.files["file"].save(dest)
