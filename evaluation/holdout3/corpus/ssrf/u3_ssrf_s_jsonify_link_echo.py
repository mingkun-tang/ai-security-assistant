def echo_link():
    link = request.args.get("link")
    return jsonify({"link": link})
