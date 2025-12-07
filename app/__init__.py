from flask import Flask
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
from flasgger import Swagger
from flask_mail import Mail
from flask_cors import CORS

from .config import Config
from .api.auth.auth_service import AuthService
from .api.register.register_service import RegService
from .api.message.hmac import MessageAuthentication

# --- NOVAS IMPORTAÇÕES ---
from .services.email_service import EmailService
from .api.notification.notification_service import NotificationService
from .api.notification import register_notification_routes
# -------------------------

# --- IMPORTAÇÕES EXISTENTES ---
from .api.carteira.carteira_service import CarteiraService
from .api.carteira import register_carteira_routes
from .api.user import register_user_routes
from .api.verify.verify_service import VerifyService
from .api.verify import register_ver_routes # Importação corrigida para usar o novo init

jwt = JWTManager()

def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.config["SWAGGER"] = {
        "swagger_ui_config": {
            "withCredentials": True
        }
    }
    # CORS para aceitar cookies e métodos HTTP personalizados
    CORS(
        app,
        supports_credentials=True,
        origins=[app.config["CORS_ORIGIN"]],
        allow_headers=["Content-Type", "Authorization"],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        expose_headers=["Content-Type"]
    )
    # Swagger
    Swagger(app)

    # JWT
    jwt.init_app(app)

    # Mongo
    mongo_client = MongoClient(app.config['MONGO_URI'])
    db_name = app.config['MONGO_DB_NAME']

    # Email (Flask-Mail object)
    mail = Mail(app)
    
    # --- NOVO: Serviço de Email Auxiliar ---
    email_service = EmailService(
        mail_service=mail,
        config=app.config
    )
    # -------------------------------------

    # Services
    # NOTA: Mantido o uso de 'mail' para compatibilidade com o AuthService existente
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
    
    # [1] Criamos o CarteiraService primeiro
    carteira_service = CarteiraService(
        mongo_client=mongo_client,
        db_name=db_name,
        config=config_class
    )
    
    verify_service = VerifyService(
        mongo_client=mongo_client,
        db_name=db_name,
        config=config_class
    )
    
    # [2] Criamos o NotificationService, INJETANDO o CarteiraService E o VerifyService
    notification_service = NotificationService(
        mongo_client=mongo_client,
        db_name=db_name,
        mail_service=email_service,
        carteira_service=carteira_service, # INJEÇÃO CRÍTICA
        config=config_class,
        verify_service=verify_service # INJEÇÃO CRÍTICA
    )
    # ----------------------------------------------------------------

    message_authentication = MessageAuthentication(
        mongo_client=mongo_client,
        db_name=db_name
    )

    # Blueprints
    from .api import api_blueprint
    from .api.auth import register_auth_routes
    from .api.register import register_reg_routes
    # from .api.verify import register_ver_routes # Removido para usar a nova função

    
    # --- ROTAS EXISTENTES ---
    register_reg_routes(api_blueprint, register_service)
    register_auth_routes(api_blueprint, auth_service, message_authentication)
    
    # --- REGISTAR ROTAS DA CARTEIRA ---
    register_carteira_routes(api_blueprint, carteira_service, message_authentication)
    # ----------------------------------
    
    register_user_routes(api_blueprint, mongo_client, db_name, message_authentication)
    
    # --- REGISTAR ROTAS DE VERIFICAÇÃO (usando o novo init) ---
    # Passamos o notification_service para o controller de verificação
    register_ver_routes(api_blueprint, verify_service, notification_service, message_authentication)
    # ---------------------------------------------------------
    
    # --- Registar Rotas de Notificação ---
    # CORREÇÃO AQUI: A função espera 4 argumentos.
    register_notification_routes(api_blueprint, notification_service, email_service, message_authentication)
    # -------------------------------------------

    app.register_blueprint(api_blueprint)


    return app