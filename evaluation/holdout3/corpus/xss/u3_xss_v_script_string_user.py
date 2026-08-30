def bootstrap_js():
    token = request.args.get("token")
    return "<script>var t = '" + token + "';</script>"
