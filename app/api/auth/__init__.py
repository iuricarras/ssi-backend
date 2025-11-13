from .auth_controller import create_auth_controller

def register_auth_routes(api_blueprint, auth_service):
    auth_bp = create_auth_controller(auth_service)
    api_blueprint.register_blueprint(auth_bp)
