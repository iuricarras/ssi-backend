from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
import os

def create_verify_controller(verify_service):
    """
    Factory que cria e retorna o controller da verificação.
    """
    bp = Blueprint('verify', __name__)
    docs = os.path.join(os.path.dirname(__file__), 'docs')

    def get_current_user_id():
        # Usa o ID do JWT para identificar o utilizador
        try:
            return get_jwt_identity() 
        except Exception:
            return None 

    @bp.post('/verify/request-verification') 
    @jwt_required()
    def request_verification():
        """Solicita uma nova verificação."""
        data = request.get_json(silent=True)
        user_id = get_current_user_id()

        if not data:
            return jsonify({'error': 'Os dados devem ser JSON.'}), 400

        # Esta chamada agora faz 3 coisas: 1. Cria o doc de verificação. 2. Gera o segredo cifrante. 3. Cria a notificação pendente.
        result = verify_service.request_verification(user_id, data)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'message': result['message']}), result['status']


    # Rota /verify/accept-verification REMOVIDA para forçar o uso da rota de notificações
    # @bp.post('/verify/accept-verification')
    # @jwt_required()
    # def accept_verification():
    #     """Aceita uma verificação solicitada. (Função de legado/teste. Deve ser feita via /notifications/respond)"""
    #     data = request.get_json(silent=True)
    #     user_id = get_current_user_id()

    #     if not data:
    #         return jsonify({'error': 'Os dados devem ser JSON.'}), 400

    #     result = verify_service.accept_verification(user_id, data)

    #     if not result['success']:
    #         return jsonify({'error': result['error']}), result['status']

    #     return jsonify({'message': result['message']}), result['status']   

    @bp.put('/verify/get-verifications/<id>')
    @jwt_required()
    def get_verifications(id):
        """Obtém uma verificação a partir do ID. Requer a chave do EC fornecida no pedido."""
        user_id = get_current_user_id()
        data = request.get_json(silent=True)

        result = verify_service.get_verification(user_id, id, data)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'verification': result['verification']}), result['status']
    

    @bp.get('/verify/get-pending')
    @jwt_required()
    def get_pending_verifications():
        """Obtém as verificações pendentes do EC (as que o utilizador ainda não respondeu)."""
        user_id = get_current_user_id()

        result = verify_service.get_pending_verifications(user_id)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'pending_verifications': result['pending_verifications']}), result['status']


    @bp.get('/verify/get-all-verifications')
    @jwt_required()
    def get_all_verifications():
        """Obtém todas as verificações solicitadas pelo EC."""
        user_id = get_current_user_id()

        result = verify_service.get_all_verifications(user_id)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'all_verifications': result['verifications']}), result['status']
    return bp