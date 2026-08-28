import httpx

def mirror_feed():
    feed = request.args.get("feed")
    return httpx.get(feed).text
