def dump_static():
    name = request.files["doc"].filename
    data = request.files["doc"].read()
    open("/srv/www/static/" + name, "wb").write(data)
