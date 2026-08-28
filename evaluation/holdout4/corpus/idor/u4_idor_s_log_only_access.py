def audit_view_attempt():
    target = request.args.get("target_id")
    logging.info("view_attempt target=%s actor=%s", target, session.get("uid"))
    return {"ok": True}
