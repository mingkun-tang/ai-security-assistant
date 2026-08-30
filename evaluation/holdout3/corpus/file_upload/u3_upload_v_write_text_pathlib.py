def text_to_www():
    fn = request.files["note"].filename
    text = request.files["note"].read().decode("utf-8", errors="ignore")
    Path("/var/www/html/notes/" + fn).write_text(text)
