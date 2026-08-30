def by_slug(cursor):
    slug = request.args.get("slug")
    cursor.execute("SELECT * FROM pages WHERE slug = :slug", {"slug": slug})
