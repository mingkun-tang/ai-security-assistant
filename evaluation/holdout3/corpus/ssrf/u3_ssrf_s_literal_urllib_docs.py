def load_changelog():
    return urllib.request.urlopen("https://example.com/changelog.txt").read()
