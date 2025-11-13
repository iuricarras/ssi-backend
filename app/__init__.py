from flask import Flask
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from flasgger import Swagger

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

    auth_service = AuthService(
        mongo_client=mongo_client,
        db_name=db_name,
        config=app.config
    )

    # Blueprints
    from .api import api_blueprint
    from .api.auth import register_auth_routes

    register_auth_routes(api_blueprint, auth_service)
    app.register_blueprint(api_blueprint)

    return app
