def audited_static_pull():
    who = request.args.get("who")
    logging.info("who=%s", who)
    return requests.get("https://cdn.partner.net/v1/ping")
