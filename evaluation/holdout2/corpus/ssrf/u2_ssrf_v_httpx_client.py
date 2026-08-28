import httpx

def probe():
    endpoint = request.args.get("endpoint")
    return httpx.get(endpoint).text
