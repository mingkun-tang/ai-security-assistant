def folder_upload():
    folder = request.form.get("folder")
    fn = request.files["f"].filename
    request.files["f"].save(folder + "/" + fn)
