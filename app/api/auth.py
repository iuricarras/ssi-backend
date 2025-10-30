from flask import jsonify, request
from . import api_blueprint
from pymongo import MongoClient
from app import db
from flask_jwt_extended import create_access_token

# Endpoint de login
@api_blueprint.post('/login')
def login():
    ## Implementar login aqui
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = db.users.find_one({"username": username, "password": password})
    if user:
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    return jsonify({"msg": "Invalid username or password"}), 401

# Endpoint de registro
@api_blueprint.post('/register')
def register():
    ## Implementar registro aqui
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    db.users.insert_one({"username": username, "password": password})

    return jsonify({"msg": "User registered successfully"}), 201

# Outros endpoints relacionados à autenticação podem ser adicionados aqui