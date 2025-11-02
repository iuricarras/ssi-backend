import json
import hmac
import hashlib
import secrets
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.collection import Collection
from flask_mail import Message

class AuthService:
    def __init__(self, mongo_client: MongoClient, db_name: str, mail, config):
        """
        Inicializa o serviço com MongoDB.
        
        Args:
            mongo_client: Cliente MongoDB
            db_name: Nome da base de dados
            mail: Instância do Flask-Mail
            config: Configurações da aplicação
        """
        self.db = mongo_client[db_name]
        self.challenges: Collection = self.db['otp_challenges']
        self.rate_limits: Collection = self.db['rate_limits']
        self.mail = mail
        self.config = config
        
        # Criar índices para melhor performance e TTL automático
        self._setup_indexes()
    
    def _setup_indexes(self):
        """Configura índices no MongoDB, incluindo TTL para expiração automática."""
        # Índice TTL para challenges (expira automaticamente)
        self.challenges.create_index(
            'expires_at',
            expireAfterSeconds=0
        )
        
        # Índice para buscar por challenge_id
        self.challenges.create_index('challenge_id', unique=True)
        
        # Índice TTL para rate limits
        self.rate_limits.create_index(
            'expires_at',
            expireAfterSeconds=0
        )
        
        # Índice composto para rate limits
        self.rate_limits.create_index([('key', 1)])

    def _otp_hash(self, code: str, challenge_id: str, email: str) -> str:
        """Gera hash HMAC do código OTP."""
        msg = f"{challenge_id}:{email}:{code}".encode()
        return hmac.new(
            self.config.OTP_SECRET_KEY.encode(),
            msg,
            hashlib.sha256
        ).hexdigest()

    def _compare_const(self, a: str, b: str) -> bool:
        """Comparação de strings em tempo constante."""
        return hmac.compare_digest(a, b)

    def _rate_key(self, prefix: str, subject: str) -> str:
        """Gera chave para rate limiting."""
        return f"rate:{prefix}:{subject}"

    def rate_limit(self, key: str, limit: int, window_sec: int) -> bool:
        """
        Implementa rate limiting usando MongoDB.
        
        Args:
            key: Chave única para o rate limit
            limit: Número máximo de tentativas
            window_sec: Janela de tempo em segundos
            
        Returns:
            True se ainda dentro do limite, False caso contrário
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=window_sec)
        
        # Tentar incrementar contador existente
        result = self.rate_limits.find_one_and_update(
            {'key': key, 'expires_at': {'$gt': now}},
            {'$inc': {'count': 1}},
            return_document=True
        )
        
        if result:
            return result['count'] <= limit
        
        # Criar novo documento se não existir
        try:
            self.rate_limits.insert_one({
                'key': key,
                'count': 1,
                'expires_at': expires_at,
                'created_at': now
            })
            return True
        except Exception:
            # Se houver erro de duplicação (race condition), tentar novamente
            result = self.rate_limits.find_one({'key': key})
            if result:
                return result['count'] <= limit
            return False

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
        
        # Calcular tempo de expiração
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.config.OTP_TTL_SEC)
        
        # Criar documento
        challenge_doc = {
            'challenge_id': challenge_id,
            'email': email,
            'code_h': self._otp_hash(code, challenge_id, email),
            'attempts': 0,
            'max_attempts': self.config.OTP_MAX_ATTEMPTS,
            'consumed': False,
            'ua': user_agent,
            'ip': ip,
            'created_at': now,
            'expires_at': expires_at
        }
        
        # Salvar no MongoDB
        try:
            self.challenges.insert_one(challenge_doc)
        except Exception as e:
            print(f"Erro ao salvar challenge: {e}")
            return None
        
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
        now = datetime.utcnow()
        
        # Buscar challenge no MongoDB
        challenge = self.challenges.find_one({
            'challenge_id': challenge_id,
            'expires_at': {'$gt': now}  # Ainda não expirou
        })
        
        if not challenge:
            return {'success': False, 'error': 'invalid_or_expired', 'status': 400}
        
        # Verificações
        if challenge.get('consumed'):
            return {'success': False, 'error': 'invalid_or_expired', 'status': 400}
        
        if challenge.get('email') != email:
            return {'success': False, 'error': 'invalid_or_expired', 'status': 400}
        
        if challenge.get('attempts', 0) >= challenge.get('max_attempts', self.config.OTP_MAX_ATTEMPTS):
            return {'success': False, 'error': 'too_many_attempts', 'status': 429}
        
        # Verificar código
        expected_h = challenge.get('code_h')
        if not self._compare_const(expected_h, self._otp_hash(code, challenge_id, email)):
            # Incrementar tentativas
            self.challenges.update_one(
                {'challenge_id': challenge_id},
                {'$inc': {'attempts': 1}}
            )
            return {'success': False, 'error': 'invalid_code', 'status': 400}
        
        # Marcar como consumido
        self.challenges.update_one(
            {'challenge_id': challenge_id},
            {'$set': {'consumed': True}}
        )
        
        return {'success': True, 'user_id': email}
    
    def cleanup_expired(self):
        """
        Método auxiliar para limpeza manual (opcional, pois o TTL já faz isso automaticamente).
        Pode ser útil para testes ou manutenção.
        """
        now = datetime.utcnow()
        
        challenges_deleted = self.challenges.delete_many({'expires_at': {'$lt': now}})
        rate_limits_deleted = self.rate_limits.delete_many({'expires_at': {'$lt': now}})
        
        return {
            'challenges_deleted': challenges_deleted.deleted_count,
            'rate_limits_deleted': rate_limits_deleted.deleted_count
        }
