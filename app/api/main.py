from . import api_blueprint
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask import jsonify
from app import db

@api_blueprint.get('/wallet')
@jwt_required()
def get_wallet():
    current_user = get_jwt_identity()
    user = db.users.find_one({"username": current_user})
    return jsonify({"status": "success"}), 200

# Para MAC, utilizar JWT
# https://www.geeksforgeeks.org/web-tech/json-web-token-jwt/
# https://medium.com/@denis.mutunga/building-a-secure-back-end-for-authentication-in-flask-a-step-by-step-guide-83c232189d15
