def measure_only():
    data = request.files["f"].read()
    return len(data)
