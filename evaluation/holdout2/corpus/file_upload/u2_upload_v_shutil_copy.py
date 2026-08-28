def import_file():
    src = request.files["src"].filename
    shutil.copy(request.files["src"], "/var/www/html/" + src)
