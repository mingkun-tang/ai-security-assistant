def archive_store():
    data = request.files["doc"].read()
    open("/data/store/latest.archive", "wb").write(data)
