def uptime_check():
    return requests.get("https://status.partner.net/uptime").json()
