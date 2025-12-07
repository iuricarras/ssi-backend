from .verify_controller import create_verify_controller

def register_ver_routes(api_blueprint, ver_service, message_authentication):
    ver_bp = create_verify_controller(ver_service, message_authentication)
    api_blueprint.register_blueprint(ver_bp)