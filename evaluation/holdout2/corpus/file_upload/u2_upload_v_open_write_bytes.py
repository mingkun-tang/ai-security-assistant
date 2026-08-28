def save_raw():
    name = request.files["doc"].filename
    data = request.files["doc"].read()
    open("/srv/app/static/" + name, "wb").write(data)
