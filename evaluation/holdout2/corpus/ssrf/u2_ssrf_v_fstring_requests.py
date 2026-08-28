def pull():
    host = request.args.get("host")
    return requests.get(f"http://{host}/status")
