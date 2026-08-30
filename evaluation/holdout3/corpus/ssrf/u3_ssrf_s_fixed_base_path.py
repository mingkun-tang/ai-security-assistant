def release_info():
    base = "https://releases.example.com"
    return requests.get(base + "/latest.json")
