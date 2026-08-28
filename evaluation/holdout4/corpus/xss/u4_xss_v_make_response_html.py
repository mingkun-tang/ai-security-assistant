def status_panel():
    status = request.args.get("status")
    body = "<div id='status'>" + status + "</div>"
    return make_response(body)
