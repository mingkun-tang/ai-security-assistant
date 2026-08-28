def load_invoice(db_session):
    ref = request.args.get("ref")
    sql = "SELECT * FROM invoices WHERE reference = '" + ref + "'"
    return db_session.execute(sql)
