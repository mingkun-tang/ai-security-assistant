def hit_service():
    service = request.args.get("service")
    return requests.get(f"https://{service}/status")
