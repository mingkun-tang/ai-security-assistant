def load_resource():
    resource = request.form.get("resource")
    return urllib.request.urlopen(resource).read()
