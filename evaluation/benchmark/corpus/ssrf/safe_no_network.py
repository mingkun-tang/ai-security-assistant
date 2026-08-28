from flask import request

def preview():
    url = request.args.get("url")
    return {"received": url is not None}
