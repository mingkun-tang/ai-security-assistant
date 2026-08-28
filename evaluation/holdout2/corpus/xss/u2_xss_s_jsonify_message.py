def api_msg():
    m = request.args.get("m")
    return jsonify({"message": m})
