from flask import Flask

app = Flask(__name__)

from .api import api_blueprint

app.register_blueprint(api_blueprint)
