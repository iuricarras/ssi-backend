from flask import request, jsonify, Blueprint
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
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
        """
        Inicia o processo de autenticação OTP
        Recebe o email do utilizador.
        Cria um challenge OTP associado ao email e IP.
        Retorna challenge_id se criado com sucesso.
        """
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
        """
        Verifica o OTP e autentica o usuário
        Recebe email, challenge_id e código OTP.
        Se for válido, gera access token e refresh token JWT.
        Define cookies JWT e retorna o nonce da sessão.
        """
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        challenge_id = data.get('challenge_id') or ''
        code = data.get('code') or ''
        result = auth_service.verify_otp(email, challenge_id, code)
        if not result['success']:
            return jsonify({'error': result['error']}), result['status']
        user_id = result['user_id']
        login_nonce = result.get("nonce")
        access = create_access_token(identity=str(user_id), additional_claims={"is_ec": False}, fresh=True)
        refresh = create_refresh_token(identity=str(user_id), additional_claims={"is_ec": False})
        resp = jsonify({'ok': True, 'session_nonce': login_nonce})
        set_access_cookies(resp, access)
        set_refresh_cookies(resp, refresh)
        return resp, 200

    @bp.get('/auth/me')
    @jwt_required()
    @swag_from(os.path.join(docs, 'me.yml'))
    def me():
        """
        Retorna informações do utilizador autenticado.
        """
        try:
            claims = get_jwt()
            email = get_jwt_identity()
            is_ec = claims.get("is_ec", False)
            print(f"DEBUG /auth/me: email={email}, is_ec={is_ec}")

            user_info = auth_service.get_user_by_email(email)
            if not user_info:
                user_info = {}
            
            user_info['id'] = get_jwt_identity()
            user_info['isEC'] = is_ec

            hmac = message_authentication.generate_hmac_signature(
                message=user_info,
                userID=str(user_info['id']),
                isEC=is_ec
            )
            print(f"DEBUG /auth/me: user_info={user_info}")
            """Retorna informações do usuário autenticado (principalmente ID)."""
            return jsonify({"data": user_info, "hmac": hmac}), 200
        except Exception as e:
            print(f"ERROR /auth/me: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"Erro ao processar /auth/me: {str(e)}"}), 500

    @bp.post('/auth/refresh')
    @jwt_required(refresh=True)
    @swag_from(os.path.join(docs, 'refresh.yml'))
    def refresh():
        """Gera novo access token usando refresh token."""
        uid = get_jwt_identity()
        claims = get_jwt()
        is_ec = claims.get("is_ec", False)
        if is_ec:
            new_access = create_access_token(identity=uid, additional_claims={"is_ec": True}, fresh=False)
        else:
            new_access = create_access_token(identity=uid, additional_claims={"is_ec": False}, fresh=False)
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
        access = create_access_token(identity="swagger", additional_claims={"is_ec": False}, fresh=True)
        refresh = create_refresh_token(identity="swagger", additional_claims={"is_ec": False})
        resp = jsonify({'ok': True})
        set_access_cookies(resp, access)
        set_refresh_cookies(resp, refresh)
        return resp, 200

     # Endpoints para Assinatura Digital
    @bp.post('/auth/signature/start')
    @swag_from(os.path.join(docs, 'signature_start.yml'))
    def auth_signature_start():
        """
        Inicia o processo de autenticação por Assinatura Digital.
        Recebe email da entidade credenciadora.
        Cria challenge com nonce.
        Retorna challenge_id e nonce.
        """
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()

        if not email:
            return jsonify({'status': 'ok'}), 200

        result = auth_service.create_signature_challenge(email)

        if result is None:
            return jsonify({'error': 'failed_to_create_challenge'}), 500

        return jsonify({
            'status': 'ok',
            'challenge_id': result['challenge_id'],
            'nonce': result['nonce']
        }), 200

    @bp.post('/auth/signature/verify')
    @swag_from(os.path.join(docs, 'signature_verify.yml'))
    def auth_signature_verify():
        """
        Verifica assinatura digital e autentica a entidade credenciadora.
        Recebe email, challenge_id e assinatura.
        Se for válido, gera tokens JWT com flag is_ec=True.
        Define cookies JWT e retorna o nonce da sessão.
        """
        data = request.get_json(silent=True) or {}
        email = (data.get('email') or '').strip().lower()
        challenge_id = data.get('challenge_id') or ''
        signature = data.get('signature') or ''

        if not all([email, challenge_id, signature]):
            return jsonify({'error': 'missing_fields'}), 400

        result = auth_service.verify_signature(email, challenge_id, signature)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']

        user_id = result['user_id']
        login_nonce = result.get("nonce")
        access = create_access_token(identity=str(user_id), additional_claims={"is_ec": True}, fresh=True)
        refresh = create_refresh_token(identity=str(user_id), additional_claims={"is_ec": True})

        resp = jsonify({'ok': True, 'session_nonce': login_nonce})
        set_access_cookies(resp, access)
        set_refresh_cookies(resp, refresh)

        return resp, 200

    return bp