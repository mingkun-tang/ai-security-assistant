def release_notes():
    return render_template("changelog.html", build="1.0.0", channel="stable")
