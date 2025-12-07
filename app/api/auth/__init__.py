from .auth_controller import create_auth_controller

def register_auth_routes(api_blueprint, auth_service, message_authentication):
    """
    register_auth_routes
    Função responsável por registar as rotas de autenticação no blueprint principal da API.
    """
    auth_bp = create_auth_controller(auth_service, message_authentication)
    api_blueprint.register_blueprint(auth_bp)
