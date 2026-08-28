import requests as http_client

def alias_pull():
    src = request.args.get("src")
    mid = src
    return http_client.get(mid)
