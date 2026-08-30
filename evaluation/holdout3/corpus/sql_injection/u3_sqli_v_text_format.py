def fetch_invoice(session):
    inv = request.args.get("inv")
    stmt = text("SELECT * FROM invoices WHERE ref = '{}'".format(inv))
    return session.execute(stmt)
