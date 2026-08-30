def rename_label(cursor):
    label = request.form.get("label")
    cursor.execute(f"UPDATE folders SET name = '{label}' WHERE id = 1")
