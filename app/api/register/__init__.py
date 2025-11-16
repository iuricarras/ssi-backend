from .register_controller import create_register_controller

def register_reg_routes(api_blueprint, reg_service):
    reg_bp = create_register_controller(reg_service)
    api_blueprint.register_blueprint(reg_bp)