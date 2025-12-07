from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app.api.message import MessageAuthentication
import os

def create_verify_controller(verify_service, notification_service, message_authentication: MessageAuthentication):
    """
    Factory que cria e retorna o controller da verificação.
    Agora usa o NotificationService para enviar pedidos.
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
        """
        Solicita uma nova verificação.
        (A requisição de verificação agora cria uma notificação para o utilizador alvo).
        """
        message = request.get_json(silent=True)
        requester_id = get_current_user_id()

        claims = get_jwt()
        is_ec = claims.get('is_ec', False)

        data = message.get('data')
        hmac = message.get('hmac')

        # O EC não precisa de assinar com a chave do utilizador, por isso isEC=False aqui no verify_hmac.
        # No entanto, a requisição é feita por uma EC (is_ec = True nos claims).
        if not message_authentication.verify_hmac_signature(data, hmac, requester_id, isEC=False):
            return jsonify({'error': 'HMAC inválido.'}), 400

        if not data:
            return jsonify({'error': 'Os dados devem ser JSON.'}), 400
        
        # Apenas ECs podem solicitar verificação
        if not is_ec:
             return jsonify({'error': 'Apenas Entidades Credenciadoras podem solicitar verificação.'}), 403

        # Dados necessários
        master_key = data.get('masterKey') # Chave do EC
        recipient_email = data.get('verificationUser') # Email do Utilizador Alvo
        verification_data_type = data.get('verificationDataType') # Tipo de dado a pedir
        
        if not master_key or not recipient_email or not verification_data_type:
            return jsonify({'error': 'masterKey, verificationUser e verificationDataType são obrigatórios.'}), 400

        # Chama o serviço de notificação para criar a notificação e a entrada de verificação
        result = notification_service.request_verification_data(
            requester_id, 
            recipient_email, 
            master_key, 
            verification_data_type
        )
        
        data = result
        hmac = message_authentication.generate_hmac_signature(
            message=data,
            userID=requester_id,
            isEC=False # Retorno para o EC (user)
        )

        return jsonify({'data': data, 'hmac': hmac}), result.get('status', 200)


    @bp.post('/verify/accept-verification')
    @jwt_required()
    def accept_verification():
        """
        Endpoint Obsoleto - A aceitação passa a ser tratada pelo /notifications/respond.
        """
        return jsonify({'error': 'A aceitação de verificação é feita através do endpoint /notifications/respond.'}), 400

    @bp.put('/verify/get-verifications/<id>')
    @jwt_required()
    def get_verifications(id):
        """Obtém uma verificação a partir do ID."""
        user_id = get_current_user_id()
        message = request.get_json(silent=True)
        data = message.get('data')
        hmac = message.get('hmac')
        
        # NOTE: O EC faz GET mas envia a masterKey no corpo, pelo que usamos POST/PUT com payload HMAC.
        if not message_authentication.verify_hmac_signature(data, hmac, user_id, isEC=False):
            return jsonify({'error': 'HMAC inválido.'}), 400

        result = verify_service.get_verification(user_id, id, data)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        data = result['verification']
        hmac = message_authentication.generate_hmac_signature(
            message=data,
            userID=user_id,
            isEC=False
        )
        return jsonify({'data': data, 'hmac': hmac}), 200
    

    @bp.get('/verify/get-all-verifications')
    @jwt_required()
    def get_all_verifications():
        """Obtém todas as verificações solicitadas pelo EC autenticado."""
        user_id = get_current_user_id()
        print(f"DEBUG get_all_verifications: user_id={user_id}")

        result = verify_service.get_all_verifications(user_id)
        print(f"DEBUG get_all_verifications: result={result}")

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        data = result['verifications']
        hmac = message_authentication.generate_hmac_signature(
            message=data,
            userID=user_id,
            isEC=False
        )
        return jsonify({'data': data, 'hmac': hmac}), 200

    @bp.get('/verify/get-pending')
    @jwt_required()
    def get_pending_verifications():
        """
        Endpoint Obsoleto - A lista de pedidos é agora tratada pelo /notifications/pending.
        """
        return jsonify({'error': 'A lista de pedidos pendentes é obtida através do endpoint /notifications/pending.'}), 400

    return bp