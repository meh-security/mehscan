import connexion
import sqlite3


def unsafe(payload):
    username = payload.get("username")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    query = f"SELECT name FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return {"name": username}


def safe(payload):
    username = payload.get("username")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute("SELECT name FROM users WHERE name = ?", (username,))
    return {"name": username}


def not_an_operation(payload):
    eval(payload)
