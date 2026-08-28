import logging
from flask import request

def log_meta():
    f = request.files["f"]
    logging.info("received upload name=%s", f.filename)
    return "ok"
