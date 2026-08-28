def health():
    return requests.get("https://status.internal/health").json()
