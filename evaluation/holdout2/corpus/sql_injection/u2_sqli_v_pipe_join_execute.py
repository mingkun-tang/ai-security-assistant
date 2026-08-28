def run(cur):
    col = request.form.get("col")
    pieces = ["SELECT * FROM ledger ORDER BY ", col]
    cur.execute("|".join(pieces))
