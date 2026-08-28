import logging
from flask import request

def audit(cursor):
    user = request.args.get("user")
    logging.info("audit requested for %s", user)
    cursor.execute("SELECT COUNT(*) FROM audits")
