import logging

def audit(cur):
    who = request.args.get("who")
    logging.warning("audit by %s", who)
    cur.execute("SELECT 1")
