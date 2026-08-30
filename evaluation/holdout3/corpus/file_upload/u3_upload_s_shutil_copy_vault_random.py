def copy_to_vault():
    src = request.files["src"]
    tmp = "/tmp/" + secrets.token_hex(8)
    src.save(tmp)
    dest = "/data/vault/" + secrets.token_hex(16) + ".bin"
    shutil.copy(tmp, dest)
