from .notification_controller import create_notification_controller

<<<<<<< Updated upstream
def register_notification_routes(api_blueprint, notification_service, mail_service, message_authentication):
    notif_bp = create_notification_controller(notification_service, message_authentication)
=======
def register_notification_routes(api_blueprint, notification_service, mail_service):
    notif_bp = create_notification_controller(notification_service, mail_service)
>>>>>>> Stashed changes
    api_blueprint.register_blueprint(notif_bp)