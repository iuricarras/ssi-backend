from flask import Flask
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from flasgger import Swagger
from datetime import timedelta
from dotenv import load_dotenv
from flask_mail import Mail, Message
import os

from .config import Config
from .api.auth.auth_service import AuthService

jwt = JWTManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Swagger
    Swagger(app)

    # JWT
    jwt.init_app(app)

    # Mongo
    mongo_client = MongoClient(app.config['MONGO_URI'])
    db_name = app.config['MONGO_DB_NAME']

    # Email
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    mail = Mail(app)

    auth_service = AuthService(
        mongo_client=mongo_client,
        db_name=db_name,
        config=config_class,
        mail_service=mail
    )

    # Blueprints
    from .api import api_blueprint
    from .api.auth import register_auth_routes

    register_auth_routes(api_blueprint, auth_service)
    app.register_blueprint(api_blueprint)


    return app
