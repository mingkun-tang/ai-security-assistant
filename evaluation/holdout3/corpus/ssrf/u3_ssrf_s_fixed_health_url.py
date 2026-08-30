def health_probe():
    return requests.get("https://monitor.internal/healthz").json()
