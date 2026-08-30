import httpx

def forward_hook():
    hook = request.json.get("hook")
    return httpx.post(hook, json={"ok": True}).text
