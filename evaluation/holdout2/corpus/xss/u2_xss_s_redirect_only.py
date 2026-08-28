def bounce():
    target = request.args.get("target")
    return redirect(target)
