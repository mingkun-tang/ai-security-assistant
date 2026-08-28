def egress_post():
    egress = request.form.get("egress")
    return requests.post(egress, data={"ping": "1"})
