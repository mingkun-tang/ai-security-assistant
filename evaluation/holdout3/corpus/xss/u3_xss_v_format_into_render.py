def page():
    heading = request.args.get("h")
    tmpl = "<header>{}</header>".format(heading)
    return render_template_string(tmpl)
