import os
from flask import Flask
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from datetime import timedelta
from dotenv import load_dotenv

client = MongoClient('localhost', 27017)

app = Flask(__name__)
db = client.flask_db

load_dotenv()

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET');
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

jwt = JWTManager(app)

from .api import api_blueprint

app.register_blueprint(api_blueprint)