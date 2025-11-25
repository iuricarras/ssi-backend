from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required
from flasgger import swag_from
import os

from .carteira_service import CarteiraService 

carteira_bp = Blueprint('carteira', __name__, url_prefix='/carteira')

def init_carteira_controller(carteira_service: CarteiraService):
    global service 
    service = carteira_service

def get_current_user_id():
    # Usa o ID do JWT para identificar o utilizador
    try:
        return get_jwt_identity() 
    except Exception:
        return None 


### Não é necessário este endpoint
### A chave é verificada e utilizada sempre que o utilizador tenta aceder aos dados 
### / , /update , etc.
# @carteira_bp.route('/verify-key', methods=['POST'])
# @jwt_required()
# @swag_from(os.path.join('docs', 'carteira.yml')) 
# def verify_key():
#     user_id = get_current_user_id()
#     if not user_id:
#         return jsonify({"message": "Não autenticado."}), 401
    
#     data = request.get_json()
#     master_key = data.get('masterKey')

#     if not master_key:
#         return jsonify({"message": "Chave mestra é obrigatória."}), 400

#     if service.verify_master_key(user_id, master_key):
#         return jsonify({"message": "Chave Mestra validada com sucesso."}), 200
#     else:
#         return jsonify({"message": "Chave Mestra incorreta. Tente novamente."}), 401 

@carteira_bp.route('/', methods=['GET'])
@jwt_required()
def get_carteira():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"message": "Não autenticado."}), 401
    
    data = request.get_json()
    master_key = data.get('masterKey')

    carteira_data = service.get_carteira_data(user_id, master_key)
    return jsonify(carteira_data), 200

@carteira_bp.route('/update', methods=['PUT'])
@jwt_required()
def update_carteira():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"message": "Não autenticado."}), 401
        
    data = request.get_json()
    master_key = data.get('masterKey')
    data = data.get('data')    
    
    if service.update_carteira_data(user_id, data, master_key):
        return jsonify({"message": "Dados atualizados."}), 200
    else:
        return jsonify({"message": "Erro interno ao salvar dados."}), 500