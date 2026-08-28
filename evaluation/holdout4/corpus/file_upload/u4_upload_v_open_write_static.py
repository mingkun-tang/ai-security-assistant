def write_static_asset():
    name = request.files["doc"].filename
    data = request.files["doc"].read()
    open("/srv/www/static/" + name, "wb").write(data)
