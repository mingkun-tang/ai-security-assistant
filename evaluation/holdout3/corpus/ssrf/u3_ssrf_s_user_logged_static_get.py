def audit_static():
    actor = request.args.get("actor")
    logging.info("actor=%s", actor)
    return requests.get("https://api.partner.com/v2/ping")
