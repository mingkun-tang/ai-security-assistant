def flash():
    note = request.args.get("note")
    return make_response("<div>" + note + "</div>")
