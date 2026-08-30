def export_ids(cursor):
    table = request.args.get("table")
    cursor.execute(f"SELECT id FROM primary_keys UNION ALL SELECT id FROM {table}")
