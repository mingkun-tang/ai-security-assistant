def invoice_by_ref(session):
    ref = request.args.get("ref")
    stmt = text("SELECT * FROM invoices WHERE reference = :ref").bindparams(ref=ref)
    return session.execute(stmt)
