def echo_url():
    url = request.args.get("url")
    return jsonify({"url": url})
