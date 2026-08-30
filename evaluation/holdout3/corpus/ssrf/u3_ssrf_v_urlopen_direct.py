def fetch_page():
    page = request.form.get("page")
    return urllib.request.urlopen(page).read()
