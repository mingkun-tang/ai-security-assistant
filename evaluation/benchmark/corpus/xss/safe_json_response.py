from flask import jsonify, request

def hello():
    name = request.args.get("name")
    return jsonify({"name": name})
