from .notification_controller import create_notification_controller

def register_notification_routes(api_blueprint, notification_service, mail_service):
    notif_bp = create_notification_controller(notification_service)
    api_blueprint.register_blueprint(notif_bp)