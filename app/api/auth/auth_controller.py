from flask import request, jsonify, Blueprint
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies
)
from flasgger import swag_from
from app.api.message import MessageAuthentication
import os

def create_auth_controller(auth_service, message_authentication: MessageAuthentication):
    """
    Factory que cria e retorna o controller de autenticação.
    """
    bp = Blueprint('auth', __name__)
    docs = os.path.join(os.path.dirname(__file__), 'docs')

    @bp.post('/auth/start')
    @swag_from(os.path.join(docs, 'start.yml'))
    def auth_start():
        """Inicia o processo de autenticação OTP"""
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
    @swag_from(os.path.join(docs, 'verify.yml'))
    def auth_verify():
        """Verifica o OTP e autentica o usuário"""
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

        resp = jsonify({'ok': True})
        set_access_cookies(resp, access)
        set_refresh_cookies(resp, refresh)
        return resp, 200

    @bp.get('/auth/me')
    @jwt_required()
    @swag_from(os.path.join(docs, 'me.yml'))
    def me():
        
        message = message_authentication.generate_hmac_signature(
            message=str(get_jwt_identity()),
            userID=str(get_jwt_identity())
        )
        print("Generated HMAC message:", message)

        valid, decoded_message = message_authentication.verify_hmac_signature(
            encoded=message,
            userID=str(get_jwt_identity())
        )
        print("Verified HMAC message:", valid, decoded_message)
        """Retorna informações do usuário autenticado."""
        return jsonify({'id': get_jwt_identity()}), 200

    @bp.post('/auth/refresh')
    @jwt_required(refresh=True)
    @swag_from(os.path.join(docs, 'refresh.yml'))
    def refresh():
        """Gera novo access token usando refresh token."""
        uid = get_jwt_identity()
        new_access = create_access_token(identity=uid, fresh=False)

        resp = jsonify({'ok': True})
        set_access_cookies(resp, new_access)
        return resp, 200

    @bp.post('/auth/logout')
    @swag_from(os.path.join(docs, 'logout.yml'))
    def logout():
        """Remove cookies JWT e finaliza sessão."""
        resp = jsonify({"msg": "logout ok"})
        unset_jwt_cookies(resp)
        return resp, 200

    @swag_from(os.path.join(docs, 'swagger_login.yml'))
    @bp.post('/auth/swagger-login')
    def swagger_login():
        access = create_access_token(identity="swagger", fresh=True)
        refresh = create_refresh_token(identity="swagger")

        resp = jsonify({'ok': True})
        set_access_cookies(resp, access)
        set_refresh_cookies(resp, refresh)
        return resp, 200

    return bp
