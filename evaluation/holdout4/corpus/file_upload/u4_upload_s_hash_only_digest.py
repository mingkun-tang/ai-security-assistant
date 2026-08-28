def digest_upload():
    content = request.files["f"].read()
    return hashlib.sha256(content).hexdigest()
