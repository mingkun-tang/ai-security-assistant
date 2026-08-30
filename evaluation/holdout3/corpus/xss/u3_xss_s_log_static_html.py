import logging

def notify():
    who = request.args.get("who")
    logging.info("visitor %s", who)
    return "<p>ok</p>"
