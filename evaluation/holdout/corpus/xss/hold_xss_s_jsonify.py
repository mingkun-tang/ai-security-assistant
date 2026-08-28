from flask import jsonify, request

def api_name():
    name = request.args.get("name")
    return jsonify({"name": name})
