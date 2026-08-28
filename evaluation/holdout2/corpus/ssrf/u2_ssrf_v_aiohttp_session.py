import aiohttp

def fetch():
    url = request.form.get("url")
    return aiohttp.ClientSession().get(url)
