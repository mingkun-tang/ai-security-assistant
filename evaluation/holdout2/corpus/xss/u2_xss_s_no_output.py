def ingest():
    blob = request.get_data()
    store(blob)
    return "ok"
