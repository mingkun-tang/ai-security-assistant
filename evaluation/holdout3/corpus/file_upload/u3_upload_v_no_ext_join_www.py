def unchecked_join():
    fname = request.files["upload"].filename
    request.files["upload"].save(os.path.join("/var/www/html", fname))
