def about_page():
    _ = request.args.get("ref")
    return render_template("about.html", year=2026, product="Acme")
