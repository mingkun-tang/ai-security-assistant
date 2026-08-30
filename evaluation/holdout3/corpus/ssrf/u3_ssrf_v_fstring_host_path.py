def status_of():
    host = request.args.get("host")
    return requests.get(f"https://{host}/v1/ready")
