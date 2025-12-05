from .user_service import UserService
from .user_controller import create_user_controller

def register_user_routes(api_blueprint, mongo_client, db_name, message_authentication):
    service = UserService(mongo_client, db_name)
    controller = create_user_controller(service, message_authentication)
    api_blueprint.register_blueprint(controller)
