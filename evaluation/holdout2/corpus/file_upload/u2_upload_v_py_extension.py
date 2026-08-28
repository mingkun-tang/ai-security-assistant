def save_script():
    fn = request.files["code"].filename
    if fn.endswith(".py"):
        request.files["code"].save("/var/www/cgi/" + fn)
