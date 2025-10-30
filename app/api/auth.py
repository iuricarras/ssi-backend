from flask import request, jsonify, make_response
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from . import api_blueprint

# Será injetado pelo main.py
auth_service = None

def init_auth_routes(service):
    """Inicializa o serviço de autenticação."""
    global auth_service
    auth_service = service

@api_blueprint.post('/auth/start')
def auth_start():
    """Inicia o processo de autenticação OTP."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    
    if not email:
        return jsonify({'status': 'ok'}), 200
    
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    user_agent = request.headers.get('User-Agent', '')
    
    result = auth_service.create_otp_challenge(email, ip, user_agent)
    
    if result is None:
        # Rate limit excedido, mas retornamos 200 por segurança
        return jsonify({'status': 'ok'}), 200
    
    return jsonify({'status': 'ok', 'challenge_id': result['challenge_id']}), 200

@api_blueprint.post('/auth/verify')
def auth_verify():
    """Verifica o código OTP e retorna tokens JWT."""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    challenge_id = data.get('challenge_id') or ''
    code = data.get('code') or ''
    
    result = auth_service.verify_otp(email, challenge_id, code)
    
    if not result['success']:
        return jsonify({'error': result['error']}), result['status']
    
    # Criar tokens JWT
    user_id = result['user_id']
    access = create_access_token(identity=str(user_id), fresh=True)
    refresh = create_refresh_token(identity=str(user_id))
    
    resp = make_response(jsonify({
        'ok': True,
        'access_token': access,
        'refresh_token': refresh
    }))
    
    return resp, 200

@api_blueprint.post('/auth/refresh')
@jwt_required(refresh=True)
def refresh():
    """Obtém novo token de acesso usando refresh token."""
    uid = get_jwt_identity()
    new_access = create_access_token(identity=uid, fresh=False)
    return jsonify({'access_token': new_access}), 200

@api_blueprint.get('/me')
@jwt_required()
def me():
    """Retorna informações do usuário autenticado."""
    return jsonify({'id': get_jwt_identity()}), 200
