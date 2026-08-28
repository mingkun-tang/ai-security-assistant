def quick_save():
    fname = request.files["upload"].filename
    request.files["upload"].save(os.path.join("/var/www", fname))
