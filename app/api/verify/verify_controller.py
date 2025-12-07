from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api.message import MessageAuthentication
import os

def create_verify_controller(verify_service, message_authentication: MessageAuthentication):
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

<<<<<<< Updated upstream
    @bp.post('/verify/request-verification') 
    @jwt_required()
    def request_verification():
        """Solicita uma nova verificação."""
        message = request.get_json(silent=True)
        user_id = get_current_user_id()

        data = message.get('data')
        hmac = message.get('hmac')

        if not message_authentication.verify_hmac_signature(data, hmac, user_id, isEC=False):
            return jsonify({'error': 'HMAC inválido.'}), 400

        if not data:
            return jsonify({'error': 'Os dados devem ser JSON.'}), 400

        result = verify_service.request_verification(user_id, data)

        data = result
        hmac = message_authentication.generate_hmac_signature(
            message=data,
            userID=user_id,
            isEC=False
        )

        return jsonify({'data': data, 'hmac': hmac}), 200
=======
    # @bp.post('/verify/request-verification') # REMOVIDO: A lógica foi movida para o NotificationService
    # @jwt_required()
    # def request_verification():
    #     """Solicita uma nova verificação."""
    #     return jsonify({'error': 'Endpoint movido. Use o fluxo de notificações.'}), 400
>>>>>>> Stashed changes


    # @bp.post('/verify/accept-verification') # REMOVIDO: A lógica foi movida para o NotificationService
    # @jwt_required()
    # def accept_verification():
    #     """Aceita uma verificação solicitada."""
    #     return jsonify({'error': 'Endpoint movido. Use o fluxo de notificações.'}), 400


    @bp.put('/verify/get-verifications/<id>')
    @jwt_required()
    def get_verifications(id):
        """Obtém uma verificação a partir do ID."""
        user_id = get_current_user_id()
        data = request.get_json(silent=True)

        result = verify_service.get_verification(user_id, id, data)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'verification': result['verifications']}), result['status']
    

    @bp.get('/verify/get-pending')
    @jwt_required()
    def get_pending_verifications():
        """Obtém as verificações pendentes do verificador (EC/Requerente)."""
        user_id = get_current_user_id()

        result = verify_service.get_pending_verifications(user_id)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'pending_verifications': result['pending_verifications']}), result['status']


    @bp.get('/verify/get-all-verifications')
    @jwt_required()
    def get_all_verifications():
        """Obtém todas as verificações."""
        user_id = get_current_user_id()

        result = verify_service.get_all_verifications(user_id)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'all_verifications': result['verifications']}), result['status']
    return bp