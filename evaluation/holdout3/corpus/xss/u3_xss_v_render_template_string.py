def preview():
    title = request.args.get("title")
    return render_template_string("<h2>" + title + "</h2>")
