def load_item(session):
    item_id = request.args.get("id")
    stmt = text("SELECT * FROM items WHERE id = :id").bindparams(id=item_id)
    return session.execute(stmt)
