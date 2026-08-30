import urllib.request as ureq

def open_alias():
    link = request.form.get("link")
    return ureq.urlopen(link).read()
