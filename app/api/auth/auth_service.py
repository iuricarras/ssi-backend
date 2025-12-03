import hmac
import hashlib
import secrets
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.collection import Collection
from flask_mail import Mail, Message
import os
from pathlib import Path
import base64 
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives import serialization 
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding

class AuthService:
    def __init__(self, mongo_client: MongoClient, db_name: str, config, mail_service: Mail):
        self.db = mongo_client[db_name]
        self.nonces: Collection = self.db["nonces"]
        self.challenges: Collection = self.db["otp_challenges"]
        self.signature_challenges = self.db["signature_challenges"]
        self.user_data: Collection = self.db["user"]
        self.config = config
        self.mail_service = mail_service 

        self._setup_indexes()

    def _setup_indexes(self):
        self.challenges.create_index("expires_at", expireAfterSeconds=0)
        self.challenges.create_index("challenge_id", unique=True)
        self.signature_challenges.create_index("expires_at", expireAfterSeconds=0)
        self.signature_challenges.create_index("challenge_id", unique=True)
        self.nonces.create_index("email")

    def _create_login_nonce(self, email: str) -> str:
        nonce = secrets.token_urlsafe(32)
        self.nonces.insert_one({
            "email": email,
            "nonce": nonce
        })
        return nonce

    def _otp_hash_once(self, code: str, challenge_id: str, email: str) -> str:
        msg = f"{challenge_id}:{email}:{code}".encode()
        return hmac.new(
            self.config["OTP_SECRET_KEY"].encode(),
            msg,
            hashlib.sha256
        ).hexdigest()

    def _otp_hash(self, code: str, challenge_id: str, email: str) -> str:
        """
        Aplica HMAC SHA256 iterado 1024 vezes.
        """
        h = self._otp_hash_once(code, challenge_id, email)
        for _ in range(1023):
            h = hmac.new(
                self.config["OTP_SECRET_KEY"].encode(),
                h.encode(),
                hashlib.sha256
            ).hexdigest()
        return h

    def _compare_const(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)

    def _generate_otp_code(self) -> str:
        return str(secrets.randbelow(900000) + 100000)

    def _get_email_template(self, otp_code: str, ttl: str, user: str) -> str:
        current_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        file_path = current_dir / 'email/template_email.html'
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                template_html = file.read()
                template_html = template_html.replace('{otp_code}', otp_code)
                template_html = template_html.replace('{time}', ttl)
                template_html = template_html.replace('{nome}', user)

        except FileNotFoundError:
            template_html = ""

        return template_html

    def create_otp_challenge(self, email: str, ip: str) -> Optional[Dict[str, Any]]:
        user = self.user_data.find_one({"email": email})
        if not user:
            return None

        self.challenges.delete_many({"email": email})
        code = self._generate_otp_code()
        challenge_id = secrets.token_urlsafe(16)

        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.config["OTP_TTL_SEC"])

        challenge_doc = {
            "challenge_id": challenge_id,
            "email": email,
            "code_h": self._otp_hash(code, challenge_id, email),
            "consumed": False,
            "ip": ip,
            "created_at": now,
            "expires_at": expires_at
        }

        try:
            self.challenges.insert_one(challenge_doc)
        except Exception as e:
            print(f"Erro ao salvar challenge: {e}")
            return None

        # Enviar email com o OTP 
        ttl = self.config["OTP_TTL_SEC"] / 60
        ttl_str = str(round(ttl))
        user = "User" # quando funcionar com a base de dados, juntar o nome
        try:
            sender_email = sender_email = self.config["MAIL_DEFAULT_SENDER"]
            html_content = self._get_email_template(code, ttl_str, user)

            msg = Message(
                subject="Seu Código de Acesso Único (OTP)",
                recipients=[email],
                sender=sender_email,
                reply_to="no-reply@bitsofme.pt"
            )
            msg.html = html_content
            self.mail_service.send(msg)

            return {"challenge_id": challenge_id}

        except Exception as e:
            self.challenges.delete_many({"challenge_id": challenge_id})
            return None

    def verify_otp(self, email: str, challenge_id: str, code: str) -> Dict[str, Any]:
        now = datetime.utcnow()

        challenge = self.challenges.find_one({
            "challenge_id": challenge_id,
            "expires_at": {"$gt": now}
        })

        if not challenge:
            return {"success": False, "error": "invalid_or_expired", "status": 400}

        if challenge.get("consumed"):
            return {"success": False, "error": "invalid_or_expired", "status": 400}

        if challenge.get("email") != email:
            return {"success": False, "error": "invalid_or_expired", "status": 400}

        expected_h = challenge.get("code_h")
        calc_h = self._otp_hash(code, challenge_id, email)

        if not self._compare_const(expected_h, calc_h):
            return {"success": False, "error": "invalid_code", "status": 400}

        self.challenges.update_one(
            {"challenge_id": challenge_id},
            {"$set": {"consumed": True}}
        )
        self.nonces.delete_many({"email": email})
        login_nonce = self._create_login_nonce(email)
        return {"success": True, "user_id": email, "nonce": login_nonce}

    # Assinatura Digital 
    def create_signature_challenge(self, email: str) -> Optional[Dict[str, Any]]:
        self.signature_challenges.delete_many({"email": email})
        
        nonce_bytes = secrets.token_bytes(32) 
        nonce_base64 = base64.b64encode(nonce_bytes).decode('utf-8')
        challenge_id = secrets.token_urlsafe(16)

        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.config["NONCE_TTL_SEC"])

        challenge_doc = {
            "challenge_id": challenge_id,
            "email": email,
            "nonce": nonce_base64, 
            "consumed": False,
            "created_at": now,
            "expires_at": expires_at
        }

        try:
            self.signature_challenges.insert_one(challenge_doc)
            return {
                "challenge_id": challenge_id,
                "nonce": nonce_base64
            }
        except Exception as e:
            print(f"Erro ao salvar challenge de assinatura: {e}")
            return None

    def verify_signature(self, email: str, challenge_id: str, signature_base64: str) -> Dict[str, Any]:
        """
        Verifica a assinatura do nonce usando a chave pública do usuário.
        """
        now = datetime.utcnow()

        challenge = self.signature_challenges.find_one({
            "challenge_id": challenge_id,
            "email": email,
            "expires_at": {"$gt": now}
        })

        if not challenge or challenge.get("consumed"):
            return {"success": False, "error": "invalid_or_expired_challenge", "status": 400}

        user_record = self.user_data.find_one({"email": email})
        if not user_record:
            return {"success": False, "error": "invalid_or_expired_challenge", "status": 400}

        public_key_pem = user_record.get("signkey")
        if not public_key_pem:
            return {"success": False, "error": "invalid_or_expired_challenge", "status": 400}

        try:
            nonce_bytes = base64.b64decode(challenge.get("nonce"))
        except Exception:
            return {"success": False, "error": "invalid_or_expired_challenge", "status": 400}

        try:
            signature_bytes = base64.b64decode(signature_base64)
        except Exception:
            return {"success": False, "error": "invalid_or_expired_challenge", "status": 400}

        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        except Exception:
            return {"success": False, "error": "invalid_or_expired_challenge", "status": 400}

        try:
            public_key.verify(
                signature_bytes,
                nonce_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.signature_challenges.update_one({"challenge_id": challenge_id}, {"$set": {"consumed": True}})
            self.nonces.delete_many({"email": email})
            
            login_nonce = self._create_login_nonce(email)
            return {"success": True, "user_id": email, "nonce": login_nonce}

        except InvalidSignature:
            return {"success": False, "error": "invalid_or_expired_challenge", "status": 400}

        except Exception as e:
            print(f"Erro na verificação de assinatura: {e}")
            return {"success": False, "error": "internal_error", "status": 500}