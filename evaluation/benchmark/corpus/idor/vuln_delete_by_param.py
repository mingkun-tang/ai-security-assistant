from flask import request

class Account:
    objects = None

def delete_account():
    account_id = request.args.get("account_id")
    Account.objects.filter(id=account_id).delete()
