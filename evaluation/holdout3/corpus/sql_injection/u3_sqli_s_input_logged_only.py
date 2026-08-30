import logging

def ping(cursor):
    who = request.args.get("who")
    logging.info("ping from %s", who)
    cursor.execute("SELECT version()")
