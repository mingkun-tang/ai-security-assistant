import logging

def greet_then_query(cursor):
    name = request.args.get("name")
    msg = "hello {}".format(name)
    logging.info(msg)
    cursor.execute("SELECT * FROM profiles WHERE active = %s", (True,))
