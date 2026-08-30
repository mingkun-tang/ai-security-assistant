def publish_file():
    name = request.files["upload"].filename
    request.files["upload"].save("/var/www/html/" + name)
