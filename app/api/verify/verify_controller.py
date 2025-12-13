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


    @bp.post('/verify/accept-verification')
    @jwt_required()
    def accept_verification():
        """Aceita uma verificação solicitada."""
        data = request.get_json(silent=True)
        user_id = get_current_user_id()

        if not data:
            return jsonify({'error': 'Os dados devem ser JSON.'}), 400

        result = verify_service.accept_verification(user_id, data)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'message': result['message']}), result['status']   

    # Accept string IDs (tokens); int converter caused 404 when ID is alphanumeric
    @bp.route('/verify/get-verifications/<verification_id>', methods=['PUT'])
    @jwt_required()
    def get_verifications(verification_id):
        """Obtém uma verificação a partir do ID."""
        print("Getting verification for ID:", verification_id)
        user_id = get_current_user_id()
        data = request.get_json(silent=True)

        result = verify_service.get_verification(user_id, verification_id, data)
        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'verification': result['verifications']}), result['status']
    

    @bp.get('/verify/get-pending')
    @jwt_required()
    def get_pending_verifications():
        """Obtém as verificações pendentes do verificador."""
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

