def fire_webhook():
    webhook = request.json.get("webhook_url")
    return urllib.request.urlopen(webhook).read()
