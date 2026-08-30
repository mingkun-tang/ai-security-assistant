def tip():
    tip = request.args.get("tip")
    return '<button title="' + tip + '">help</button>'
