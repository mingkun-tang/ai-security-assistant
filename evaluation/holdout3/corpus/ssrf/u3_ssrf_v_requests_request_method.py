def proxy_get():
    endpoint = request.args.get("endpoint")
    return requests.request("GET", endpoint).text
