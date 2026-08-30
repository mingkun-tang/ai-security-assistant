def search_docs(cursor):
    builder = ["SELECT title FROM docs"]
    term = request.args.get("q")
    builder.extend(["WHERE body LIKE '%", term, "%'"])
    cursor.execute("".join(builder))
