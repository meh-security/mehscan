@client.get("/admin")
@app.fetch("/admin")
@user_required
@check_permission("admin.read")
def admin():
    return "ok"
