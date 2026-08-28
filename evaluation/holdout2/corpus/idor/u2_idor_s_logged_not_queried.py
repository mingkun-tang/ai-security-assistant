def log_request():
    target = request.args.get("target")
    logging.info("target=%s", target)
    return {"status": "ok"}
