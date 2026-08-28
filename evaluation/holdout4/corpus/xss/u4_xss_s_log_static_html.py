def maintenance_page():
    note = request.args.get("note")
    app.logger.info("maintenance note=%s", note)
    return "<html><body><p>Down for maintenance</p></body></html>"
