from flask import Blueprint, jsonify, request

def create_user_controller(user_service):

    user_bp = Blueprint("user", __name__, url_prefix="/user")

    @user_bp.get("/search")
    def get_usernames():
        query = request.args.get("query", "")
        users = user_service.get_usernames(query)
        return jsonify(users), 200

    return user_bp
