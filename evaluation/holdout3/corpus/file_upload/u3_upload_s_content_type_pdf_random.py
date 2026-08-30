def pdf_gate():
    f = request.files["pdf"]
    if f.content_type != "application/pdf":
        raise ValueError("pdf")
    f.save("/data/pdf/" + secrets.token_hex(12) + ".pdf")
