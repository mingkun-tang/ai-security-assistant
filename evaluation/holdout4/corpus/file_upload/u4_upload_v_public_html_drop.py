def public_html_drop():
    name = request.files["img"].filename
    request.files["img"].save("/var/www/html/public/" + name)
