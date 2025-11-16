from flask import Flask
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from flasgger import Swagger
from flask_mail import Mail
from flask_cors import CORS

from .config import Config
from .api.auth.auth_service import AuthService
from .api.register.register_service import RegService

jwt = JWTManager()

def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config["SWAGGER"] = {
        "swagger_ui_config": {
            "withCredentials": True
        }
    }
    # CORS para aceitar cookies
    CORS(
        app,
        supports_credentials=True,
        origins=[app.config["CORS_ORIGIN"]]
    )
    # Swagger
    Swagger(app)

    # JWT
    jwt.init_app(app)

    # Mongo
    mongo_client = MongoClient(app.config['MONGO_URI'])
    db_name = app.config['MONGO_DB_NAME']

    # Email
    mail = Mail(app)

    # Services
    auth_service = AuthService(
        mongo_client=mongo_client,
        db_name=db_name,
        config=app.config,
        mail_service=mail
    )

    register_service = RegService(
        mongo_client=mongo_client,
        db_name=db_name,
        config=config_class
    )

    # Blueprints
    from .api import api_blueprint
    from .api.auth import register_auth_routes
    from .api.register import register_reg_routes
    register_reg_routes(api_blueprint, register_service)

    register_auth_routes(api_blueprint, auth_service)
    app.register_blueprint(api_blueprint)


    return app
