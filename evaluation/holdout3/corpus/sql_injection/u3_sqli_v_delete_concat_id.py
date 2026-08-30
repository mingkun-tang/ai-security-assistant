def remove_session(cursor):
    sid = request.form.get("sid")
    cursor.execute("DELETE FROM sessions WHERE id = " + sid)
