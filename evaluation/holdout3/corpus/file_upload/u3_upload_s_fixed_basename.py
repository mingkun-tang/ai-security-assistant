def fixed_avatar():
    data = request.files["avatar"].read()
    open("/data/avatars/profile.png", "wb").write(data)
