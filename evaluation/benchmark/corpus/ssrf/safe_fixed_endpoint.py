import requests

def metrics():
    requests.get("https://metrics.internal/v1/summary")
