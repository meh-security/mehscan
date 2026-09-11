@app.get("/admin")
@login_required
@permission_required("admin.read")
def admin():
    return "ok"
