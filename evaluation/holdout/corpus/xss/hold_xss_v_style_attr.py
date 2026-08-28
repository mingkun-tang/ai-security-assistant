from flask import request

def badge():
    color = request.args.get("color")
    return f"<span style='color:{color}'>VIP</span>"
