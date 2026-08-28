def fuzzy_title(db):
    import sqlalchemy as sa
    run = db.execute
    q = request.args.get("q")
    needle = q
    pattern = "%" + needle + "%"
    run("SELECT title FROM articles WHERE title LIKE '" + pattern + "'")
