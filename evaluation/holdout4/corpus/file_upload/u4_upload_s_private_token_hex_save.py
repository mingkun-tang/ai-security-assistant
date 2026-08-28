def private_token_store():
    f = request.files["file"]
    f.save("/var/app/private/" + secrets.token_hex(16) + ".bin")
