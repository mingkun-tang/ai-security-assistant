def outbound():
    dest = request.args.get("dest")
    return redirect(dest)
