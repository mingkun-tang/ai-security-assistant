def api_profile():
    name = request.args.get("name")
    return jsonify({"name": name, "ok": True})
