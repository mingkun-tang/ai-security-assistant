def find_sku(session):
    sku = request.args.get("sku")
    return session.execute(text(f"SELECT id FROM catalog WHERE sku = '{sku}'"))
