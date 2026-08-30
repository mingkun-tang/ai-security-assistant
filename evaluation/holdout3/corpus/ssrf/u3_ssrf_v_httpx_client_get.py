from httpx import Client

def client_get():
    loc = request.args.get("loc")
    with Client() as client:
        return client.get(loc).text
