import requests

def health():
    requests.get("https://status.example.com/api/health")
