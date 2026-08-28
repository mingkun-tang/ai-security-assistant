from flask import request

class Account:
    objects = None

def balance():
    account_id = request.args.get("account_id")
    return Account.objects.filter(id=account_id).first()
