def patch(cur):
    val = request.form.get("val")
    cur.execute("UPDATE settings SET value = '" + val + "' WHERE id = 1")
