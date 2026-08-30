def sorted_posts(cursor):
    direction = request.args.get("dir")
    cursor.execute("SELECT * FROM posts ORDER BY created_at " + direction)
