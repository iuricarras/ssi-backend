from flask import Flask
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from redis import Redis

from .config import Config
from .services.auth_service import AuthService

jwt = JWTManager()
mail = Mail()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Inicializar extensões
    jwt.init_app(app)
    
    # CORS
    CORS(app, resources={r"/*": {"origins": app.config['CORS_ORIGIN']}})
    
    # Mail (opcional)
    mail_instance = None
    if app.config['MAIL_SERVER']:
        mail.init_app(app)
        mail_instance = mail
    
    # Redis
    redis_client = Redis.from_url(app.config['REDIS_URL'], decode_responses=True)
    
    # Inicializar serviço de autenticação
    auth_service = AuthService(redis_client, mail_instance, app.config)
    
    # Registrar blueprints
    from .api import api_blueprint
    from .api.auth import init_auth_routes
    
    init_auth_routes(auth_service)
    app.register_blueprint(api_blueprint)
    
    return app
