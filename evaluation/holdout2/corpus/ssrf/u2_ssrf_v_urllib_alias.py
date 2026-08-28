import urllib.request as urlreq

def load():
    link = request.form.get("link")
    return urlreq.urlopen(link)
