from flask import Flask

from .views import items

app = Flask(__name__)
app.register_blueprint(items, url_prefix="/items")
app.run(debug=True, host="127.0.0.1")
