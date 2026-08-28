def release_manifest():
    root = "https://releases.partner.net"
    return requests.get(root + "/manifest.json")
