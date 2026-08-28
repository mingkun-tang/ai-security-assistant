def archive():
    fn = request.files["doc"].filename
    request.files["doc"].save("/var/app/archives/" + fn)
