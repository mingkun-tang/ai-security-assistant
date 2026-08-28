def order_detail(session):
    oid = request.args.get("oid")
    return session.execute(
        text("SELECT * FROM orders WHERE id = :oid"),
        {"oid": oid},
    )
