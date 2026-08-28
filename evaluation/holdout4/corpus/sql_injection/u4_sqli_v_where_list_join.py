def audit_rows(cursor):
    status = request.args.get("status")
    parts = [
        "SELECT * FROM audit_log WHERE 1=1",
        "AND status = '" + status + "'",
        "ORDER BY created_at DESC",
    ]
    cursor.execute(" ".join(parts))
