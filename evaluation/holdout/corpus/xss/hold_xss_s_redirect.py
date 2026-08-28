from flask import redirect, request

def go():
    target = request.args.get("next")
    return redirect(target)
