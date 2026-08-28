def fixed_logo_write():
    data = request.files["logo"].read()
    open("/data/branding/logo.png", "wb").write(data)
