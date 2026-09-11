import codecs
import flask
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/unsafe", methods=["GET"])
def unsafe():
    value = request.args.get("q", "")
    connection = sqlite3.connect("app.db")
    cur = connection.cursor()
    query = f"SELECT name FROM users WHERE name = '{value}'"
    cur.execute(query)
    return f"<p>{value}</p>"


@app.route("/safe-query", methods=["GET"])
def safe_query():
    value = request.args.get("q", "")
    connection = sqlite3.connect("app.db")
    cur = connection.cursor()
    cur.execute("SELECT name FROM users WHERE name = ?", (value,))
    return "ok"


@app.route("/file", methods=["GET"])
def read_file():
    path = request.cookies.get("path", "fallback.txt")
    return codecs.open(path, "r", "utf-8").read()


@app.route("/leave", methods=["GET"])
def leave():
    return flask.redirect(request.args.get("next", "/"))
