import aiohttp

def pull_remote():
    remote = request.args.get("remote")
    return aiohttp.ClientSession().get(remote)
