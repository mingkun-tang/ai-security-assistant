def snippet():
    html = request.args.get("html")
    return render_template_string("{{ content }}", content=html)
