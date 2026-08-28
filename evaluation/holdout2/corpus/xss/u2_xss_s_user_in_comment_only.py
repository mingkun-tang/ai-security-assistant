def debug_note():
    note = request.args.get("note")
    logging.info("note=%s", note)
    return "<p>logged</p>"
