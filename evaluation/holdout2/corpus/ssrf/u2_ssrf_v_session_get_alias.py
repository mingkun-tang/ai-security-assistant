import requests as rq

def ping():
    loc = request.args.get("loc")
    return rq.get(loc)
