def relay():
    target = request.form.get("target")
    return requests.post(target, data={"ping": "1"})
