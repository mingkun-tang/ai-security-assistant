def scrape_metrics():
    return requests.get("https://metrics.internal/prometheus").text
