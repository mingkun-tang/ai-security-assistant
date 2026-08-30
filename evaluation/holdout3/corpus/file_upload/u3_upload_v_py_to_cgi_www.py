def accept_py_cgi():
    fn = request.files["code"].filename
    if fn.endswith(".py"):
        request.files["code"].save("/var/www/cgi-bin/" + fn)
