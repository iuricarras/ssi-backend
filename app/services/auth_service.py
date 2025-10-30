import json
import hmac
import hashlib
import secrets
from typing import Optional, Dict, Any
from redis import Redis
from flask_mail import Message

class AuthService:
    def __init__(self, redis_client: Redis, mail, config):
        self.redis = redis_client
        self.mail = mail
        self.config = config
    
    def _otp_hash(self, code: str, challenge_id: str, email: str) -> str:
        msg = f"{challenge_id}:{email}:{code}".encode()
        return hmac.new(
            self.config.OTP_SECRET_KEY.encode(),
            msg,
            hashlib.sha256
        ).hexdigest()
    
    def _compare_const(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)
    
    def _redis_key(self, challenge_id: str) -> str:
        return f"login:challenge:{challenge_id}"
    
    def _rate_key(self, prefix: str, subject: str) -> str:
        return f"rate:{prefix}:{subject}"
    
    def rate_limit(self, key: str, limit: int, window_sec: int) -> bool:
        c = self.redis.incr(key)
        if c == 1:
            self.redis.expire(key, window_sec)
        return c <= limit
    
    def create_otp_challenge(self, email: str, ip: str, user_agent: str) -> Optional[Dict[str, Any]]:
        """
        Cria um desafio OTP e envia por email.
        Retorna None se rate limit foi excedido.
        """
        # Rate limiting
        if not self.rate_limit(self._rate_key('start_ip', ip), limit=10, window_sec=300):
            return None
        
        if not self.rate_limit(self._rate_key('start_email', email), limit=5, window_sec=300):
            return None
        
        # Gerar challenge e código
        challenge_id = secrets.token_urlsafe(16)
        code = ''.join(secrets.choice('0123456789') for _ in range(self.config.OTP_DIGITS))
        
        # Criar payload
        payload = {
            'email': email,
            'code_h': self._otp_hash(code, challenge_id, email),
            'attempts': 0,
            'max_attempts': self.config.OTP_MAX_ATTEMPTS,
            'consumed': False,
            'ua': user_agent,
            'ip': ip,
        }
        
        # Salvar no Redis
        self.redis.setex(
            self._redis_key(challenge_id),
            self.config.OTP_TTL_SEC,
            json.dumps(payload)
        )
        
        # Enviar email
        self._send_otp_email(email, code)
        
        return {'challenge_id': challenge_id}
    
    def _send_otp_email(self, email: str, code: str):
        """Envia o código OTP por email ou imprime no console."""
        try:
            if self.mail:
                msg = Message(subject='Seu código de login', recipients=[email])
                msg.body = f"Seu código é: {code}. Ele expira em {self.config.OTP_TTL_SEC // 60} minutos."
                self.mail.send(msg)
            elif self.config.SEND_CONSOLE:
                print(f"[DEV] OTP para {email}: {code}")
        except Exception as e:
            print(f"Erro ao enviar email: {e}")
    
    def verify_otp(self, email: str, challenge_id: str, code: str) -> Dict[str, Any]:
        """
        Verifica o código OTP.
        Retorna {'success': True, 'user_id': ...} ou {'success': False, 'error': ...}
        """
        key = self._redis_key(challenge_id)
        raw = self.redis.get(key)
        
        if not raw:
            return {'success': False, 'error': 'invalid_or_expired', 'status': 400}
        
        try:
            payload = json.loads(raw)
        except Exception:
            return {'success': False, 'error': 'invalid_or_expired', 'status': 400}
        
        # Verificações
        if payload.get('consumed'):
            return {'success': False, 'error': 'invalid_or_expired', 'status': 400}
        
        if payload.get('email') != email:
            return {'success': False, 'error': 'invalid_or_expired', 'status': 400}
        
        if payload.get('attempts', 0) >= payload.get('max_attempts', self.config.OTP_MAX_ATTEMPTS):
            return {'success': False, 'error': 'too_many_attempts', 'status': 429}
        
        # Verificar código
        expected_h = payload.get('code_h')
        if not self._compare_const(expected_h, self._otp_hash(code, challenge_id, email)):
            payload['attempts'] = payload.get('attempts', 0) + 1
            self.redis.set(key, json.dumps(payload), keepttl=True)
            return {'success': False, 'error': 'invalid_code', 'status': 400}
        
        # Marcar como consumido
        payload['consumed'] = True
        self.redis.set(key, json.dumps(payload), keepttl=True)
        
        return {'success': True, 'user_id': email}
