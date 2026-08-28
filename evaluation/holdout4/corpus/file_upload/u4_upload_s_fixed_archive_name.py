def archive_fixed_dest():
    data = request.files["doc"].read()
    open("/data/store/current.archive", "wb").write(data)
