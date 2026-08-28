def bounce_client():
    next_url = request.args.get("next")
    return redirect(next_url)
