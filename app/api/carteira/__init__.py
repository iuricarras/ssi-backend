from .carteira_controller import carteira_bp, init_carteira_controller

def register_carteira_routes(api_blueprint, carteira_service, message_authentication): 
    init_carteira_controller(carteira_service, message_authentication)
    api_blueprint.register_blueprint(carteira_bp)