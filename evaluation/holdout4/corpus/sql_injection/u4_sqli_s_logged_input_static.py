def health_probe(cursor):
    probe = request.args.get("probe")
    app.logger.info("probe=%s", probe)
    cursor.execute("SELECT 1 AS ok")
    return cursor.fetchone()
