def audit_trail(session):
    actor = request.args.get("actor")
    session.execute("SELECT * FROM audit WHERE actor = '" + actor + "'")
