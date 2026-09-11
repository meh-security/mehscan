from flask import Blueprint, g, redirect, render_template, request
from flask_login import current_user

from .models import Item

items = Blueprint("items", __name__)


@items.route("/<int:item_id>")
def unsafe_item(item_id):
    item = Item.query.get(item_id)
    return render_template("item.html", items=[item])


@items.route("/protected/<int:item_id>", methods=["POST"])
def protected_item(item_id):
    if "username" not in g.session:
        return redirect("/login")
    item = Item.query.filter_by(id=item_id, owner=current_user).first()
    return {"id": item.id}


@items.route("/api", methods=["POST"])
def protected_api():
    username = authenticate(request)
    if not username:
        return {"error": "unauthorized"}, 401
    return {"ok": True}
