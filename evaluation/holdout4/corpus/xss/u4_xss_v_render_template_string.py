def preview_snippet():
    body = request.form.get("body")
    return render_template_string("<section>{{ body|safe }}</section>", body=body)
