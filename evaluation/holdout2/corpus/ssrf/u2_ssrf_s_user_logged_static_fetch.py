def audit_fetch():
    who = request.args.get("who")
    logging.info("fetch by %s", who)
    return requests.get("https://api.example.com/v1/ping")
