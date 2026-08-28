def show_dashboard():
    title = request.args.get("title", "Home")
    return render_template("dashboard.html", title=title)
