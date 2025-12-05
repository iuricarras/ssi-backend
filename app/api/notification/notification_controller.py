from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
import os

from app.services.email_service import EmailService 

def create_notification_controller(notification_service):
    """
    Factory que cria e retorna o controller de Notificações.
    """
    bp = Blueprint('notification', __name__, url_prefix='/notifications')

    def get_current_user_id():
        try:
            return get_jwt_identity() 
        except Exception:
            return None 

    @bp.post('/request-certificate') 
    @jwt_required()
    def request_certificate():
        """
        Endpoint da Entidade Certificadora (EC) para requisição de adição de certificado.
        Requer token JWT da EC.
        """
        requester_id = get_current_user_id()
        data = request.get_json(silent=True)
        
        claims = get_jwt()
        is_ec = claims.get('is_ec', False)

        if not data:
            return jsonify({'error': 'Os dados devem ser JSON.'}), 400
            
        if not is_ec:
             return jsonify({'error': 'Apenas Entidades Certificadoras podem submeter requisições de certificado.'}), 403

        recipient_email = data.get('recipient_email')
        certificate_data = data.get('certificate_data')
        
        if not recipient_email or not certificate_data:
            return jsonify({'error': 'O email do destinatário e os dados do certificado são obrigatórios.'}), 400

        result = notification_service.request_certificate_addition(requester_id, recipient_email, certificate_data)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'message': result['message'], 'notification_id': result.get('notification_id')}), result['status']


    @bp.get('/pending')
    @jwt_required()
    def get_pending_notifications():
        """
        Obtém todas as notificações pendentes para o utilizador atual.
        """
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"message": "Não autenticado."}), 401

        notifications = notification_service.get_pending_notifications(user_id)
        
        return jsonify({'notifications': notifications}), 200

    @bp.post('/respond')
    @jwt_required()
    def respond_to_notification():
        """
        O utilizador aceita ou recusa uma notificação pendente.
        Requer 'notification_id', 'action' (ACCEPT/REJECT) e 'master_key' (se for ACCEPT de certificado).
        """
        user_id = get_current_user_id()
        if not user_id:
            return jsonify({"message": "Não autenticado."}), 401

        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Os dados devem ser JSON.'}), 400

        notification_id = data.get('notification_id')
        action = data.get('action') 
        master_key = data.get('master_key')

        if not notification_id or not action:
            return jsonify({'error': 'O ID da notificação e a ação são obrigatórios.'}), 400

        action = action.upper()
        if action not in ["ACCEPT", "REJECT"]:
            return jsonify({'error': 'A ação deve ser "ACCEPT" ou "REJECT".'}), 400

        result = notification_service.respond_to_notification(user_id, notification_id, action, master_key)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        return jsonify({'message': result['message']}), result['status']

    return bp