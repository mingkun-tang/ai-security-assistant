def store():
    note = request.form.get("note")
    cache = {}
    cache["note"] = note
    return None
