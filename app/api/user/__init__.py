from .user_service import UserService
from .user_controller import create_user_controller

def register_user_routes(api_blueprint, mongo_client, db_name):
    service = UserService(mongo_client, db_name)
    controller = create_user_controller(service)
    api_blueprint.register_blueprint(controller)
