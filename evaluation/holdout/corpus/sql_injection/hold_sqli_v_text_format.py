from flask import request

def audit(engine):
    tenant = request.args.get("tenant")
    engine.execute("SELECT * FROM logs WHERE tenant = '{}'".format(tenant))
