import logging

def report(cursor):
    note = request.args.get("note")
    logging.debug("operator note: %s", note)
    # note is for operators only
    cursor.execute("SELECT COUNT(*) FROM reports")
