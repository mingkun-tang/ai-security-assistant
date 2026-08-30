def api_msg():
    msg = request.args.get("msg")
    return jsonify({"message": msg})
