def log_target():
    target = request.args.get("target")
    logging.info("target=%s", target)
    return {"ok": True}
