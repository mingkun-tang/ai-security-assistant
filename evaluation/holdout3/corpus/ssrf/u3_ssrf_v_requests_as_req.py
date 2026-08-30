import requests as req

def mirror_url():
    src = request.args.get("src")
    return req.get(src)
