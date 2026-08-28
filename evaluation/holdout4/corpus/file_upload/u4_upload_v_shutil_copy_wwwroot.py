def mirror_into_www():
    name = request.files["blob"].filename
    shutil.copy(request.files["blob"], "/var/www/" + name)
