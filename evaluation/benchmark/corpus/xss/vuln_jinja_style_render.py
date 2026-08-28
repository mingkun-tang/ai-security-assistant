from flask import render_template_string, request

def preview():
    body = request.args.get("body")
    return render_template_string("<p>{{ body }}</p>", body=body)
