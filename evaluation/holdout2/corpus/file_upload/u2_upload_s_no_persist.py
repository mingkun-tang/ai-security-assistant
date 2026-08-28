def scan_only():
    content = request.files["f"].read()
    return hashlib.sha256(content).hexdigest()
