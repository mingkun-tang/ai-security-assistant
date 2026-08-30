def bounce_out():
    dest = request.args.get("dest")
    return redirect(dest)
