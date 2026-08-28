def fail_page():
    detail = request.args.get("err")
    return (
        "<html><body><h1>Error</h1><pre>"
        + detail
        + "</pre></body></html>"
    ), 400
