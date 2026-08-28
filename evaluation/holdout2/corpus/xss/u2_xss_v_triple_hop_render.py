def panel():
    t = request.args.get("t")
    u = t
    v = u
    return render_template_string("<p>{{ v }}</p>", v=v)
