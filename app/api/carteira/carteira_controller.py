from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
from flasgger import swag_from
import os

from .carteira_service import CarteiraService 
from app.api.message import MessageAuthentication
import json as JSON
carteira_bp = Blueprint('carteira', __name__, url_prefix='/carteira')

def init_carteira_controller(carteira_service: CarteiraService, message_authentication: MessageAuthentication):
    global service 
    service = carteira_service
    global message_authentication_service
    message_authentication_service = message_authentication
def get_current_user_id():
    """
    Obtém o ID do utilizador autenticado a partir do JWT.
    """
    # Usa o ID do JWT para identificar o utilizador
    try:
        return get_jwt_identity() 
    except Exception:
        return None 

@carteira_bp.route('/', methods=['POST'])
@jwt_required()
def get_carteira():
    """
    Obtém os dados da carteira.
    Requer 'masterKey' no corpo da requisição.
    Valida integridade do payload com HMAC.
    Se for válido, chama service.get_carteira_data(user_id, masterKey).
    Retorna dados da carteira + assinatura HMAC.
    Se a masterKey for inválida, retorna erro 400.
    """
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"message": "Não autenticado."}), 401
    
    message = request.get_json()
    data = message.get('data')
    hmac = message.get('hmac')
    print("Received data for HMAC verification:", data)
    if not message_authentication_service.verify_hmac_signature(data, hmac, user_id, isEC=False):
        return jsonify({"message": "HMAC inválido."}), 400
    
    master_key = data.get('masterKey')
    try:
        carteira_data = service.get_carteira_data(user_id, master_key)
        hmac = message_authentication_service.generate_hmac_signature(
            message=carteira_data,
            userID=user_id,
            isEC=False
        )
        return jsonify({"data": carteira_data, "hmac": hmac}), 200
    except ValueError:
        return jsonify({"message": "Erro de decifra. Chave Mestra inválida."}), 400

@carteira_bp.route('/update', methods=['PUT'])
@jwt_required()
def update_carteira():
    """
    Atualiza os dados da carteira.
    Requer 'masterKey' e 'data' no corpo da requisição.
    Valida a integridade do payload com HMAC.
    Se for válido, chama service.update_carteira_data(user_id, data, masterKey).
    Retorna uma mensagem de sucesso + assinatura HMAC.
    Se a masterKey for inválida, retorna erro 400.
    """
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"message": "Não autenticado."}), 401
        
    message = request.get_json()
    data = message.get('data')
    hmac = message.get('hmac')
    
    print("Received data for HMAC verification:", JSON.dumps(data, sort_keys=True, separators=(',', ':')))
    if not message_authentication_service.verify_hmac_signature(data, hmac, user_id, isEC=False):
        return jsonify({"message": "HMAC inválido."}), 400
    
    master_key = data.get('masterKey')
    data = data.get('data')
    
    try:
        if service.update_carteira_data(user_id, data, master_key):
            data = {"message": "Dados atualizados."}
            hmac = message_authentication_service.generate_hmac_signature(
                message=data,
                userID=user_id,
                isEC=False
            )
            return jsonify({"data": data, "hmac": hmac}), 200
        else:
            return jsonify({"message": "Erro interno ao guardar os dados."}), 500
    except ValueError:
        return jsonify({"message": "Chave Mestra inválida."}), 400



@carteira_bp.route('/user/<username>/profile', methods=['GET'])
@jwt_required()
def get_user_profile(username):
    """
    Retorna o perfil do utilizador com base no username.
    Obtém dados básicos (nome, email, username).
    Gera assinatura HMAC para garantir integridade.
    """
    user_id = get_current_user_id()
    user = service.get_user_by_username(username)
    if not user:
        return jsonify({"message": "Utilizador não encontrado."}), 404
    
    hmac = message_authentication_service.generate_hmac_signature(
        message=user,
        userID=user_id,
        isEC=False
    )   
    return jsonify({"data": user, "hmac": hmac}), 200

@carteira_bp.route('/user/<username>', methods=['GET'])
@jwt_required()
def get_user_carteira(username):
    """
    Retorna os dados públicos (dados pessoais e certificados) da carteira de um utilizador.
    Inclui dados pessoais e certificados.
    Obtém dados via service.get_carteira_public_data(email).
    Gera assinatura HMAC para garantir integridade.
    """
    user_id = get_current_user_id()
    user = service.get_user_by_username(username)
    if not user:
        return jsonify({"message": "Utilizador não encontrado."}), 404

    carteira_data = service.get_carteira_public_data(user['email'])

    response_data = {
        "personalData": carteira_data.get("personalData", []),
        "certificates": carteira_data.get("certificates", [])
    }
    

    hmac = message_authentication_service.generate_hmac_signature(
        message=response_data,
        userID=user_id,
        isEC=False
    )

    return jsonify({"data": response_data, "hmac": hmac}), 200
