from flask import request, jsonify, Blueprint
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from flasgger import swag_from
import os

def create_auth_controller(auth_service):
    """
    Factory que cria e retorna o controller de autenticação.
    """
    bp = Blueprint('auth', __name__)
    docs = os.path.join(os.path.dirname(__file__), 'docs')

    @bp.post('/auth/start')
    @swag_from(os.path.join(docs, 'auth_start.yml'))
    def auth_start():
        """Inicia o processo de autenticação OTP (mockado)."""
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()

        if not email:
            return jsonify({'status': 'ok'}), 200

        ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')

        result = auth_service.create_otp_challenge(email, ip)

        if result is None:
            return jsonify({'status': 'ok'}), 200

        return jsonify({
            'status': 'ok',
            'challenge_id': result['challenge_id']
        }), 200

    @bp.post('/auth/verify')
    @swag_from(os.path.join(docs, 'auth_verify.yml'))
    def auth_verify():
        """Verifica o OTP mockado e retorna tokens JWT."""
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        challenge_id = data.get('challenge_id') or ''
        code = data.get('code') or ''

        result = auth_service.verify_otp(email, challenge_id, code)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        user_id = result['user_id']
        access = create_access_token(identity=str(user_id), fresh=True)
        refresh = create_refresh_token(identity=str(user_id))

        return jsonify({
            'ok': True,
            'access_token': access,
            'refresh_token': refresh
        }), 200
    

    # Endpoints para Assinatura Digital
    
    @bp.post('/auth/signature/start')
    @swag_from(os.path.join(docs, 'auth_signature_start.yml'))
    def auth_signature_start():
        """Inicia o processo de autenticação por Assinatura Digital."""
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()

        if not email:
            return jsonify({'error': 'email_required'}), 400

        result = auth_service.create_signature_challenge(email)

        if result is None:
            return jsonify({'error': 'failed_to_create_challenge'}), 500

        return jsonify({
            'status': 'ok',
            'challenge_id': result['challenge_id'],
            'nonce': result['nonce'] # Retorna o nonce para o cliente assinar
        }), 200

    @bp.post('/auth/signature/verify')
    @swag_from(os.path.join(docs, 'auth_signature_verify.yml'))
    def auth_signature_verify():
        """Verifica a assinatura digital e retorna tokens JWT."""
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        challenge_id = data.get('challenge_id') or ''
        signature = data.get('signature') or ''
        # Nota: public_key_pem está sendo passado no corpo para este protótipo
        public_key_pem = data.get('public_key_pem') or '' 

        if not all([email, challenge_id, signature, public_key_pem]):
             return jsonify({'error': 'missing_fields'}), 400

        result = auth_service.verify_signature(email, challenge_id, signature, public_key_pem)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        user_id = result['user_id']
        access = create_access_token(identity=str(user_id), fresh=True)
        refresh = create_refresh_token(identity=str(user_id))

        return jsonify({
            'ok': True,
            'access_token': access,
            'refresh_token': refresh
        }), 200

    @bp.get('/me')
    @jwt_required()
    @swag_from(os.path.join(docs, 'me.yml'))
    def me():
        """Retorna o usuário autenticado."""
        return jsonify({'id': get_jwt_identity()}), 200

    @bp.post('/auth/refresh')
    @jwt_required(refresh=True)
    @swag_from(os.path.join(docs, 'refresh.yml'))
    def refresh():
        """Gera novo access token usando refresh token."""
        uid = get_jwt_identity()
        new_access = create_access_token(identity=uid, fresh=False)
        return jsonify({'access_token': new_access}), 200
    


    return bp
