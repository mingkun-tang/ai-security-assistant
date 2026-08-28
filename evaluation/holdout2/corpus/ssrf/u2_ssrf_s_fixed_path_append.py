def version():
    base = "https://api.example.com"
    return requests.get(base + "/version")
