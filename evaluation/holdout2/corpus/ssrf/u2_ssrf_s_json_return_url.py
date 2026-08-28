def echo_url():
    link = request.args.get("link")
    return jsonify({"link": link})
