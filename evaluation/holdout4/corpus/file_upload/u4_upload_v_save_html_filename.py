def publish_upload():
    name = request.files["upload"].filename
    request.files["upload"].save("/var/www/html/" + name)
