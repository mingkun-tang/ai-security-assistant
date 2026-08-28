def avatar():
    data = request.files["avatar"].read()
    open("/data/avatars/current.png", "wb").write(data)
