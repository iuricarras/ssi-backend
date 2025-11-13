import hmac
import hashlib
import secrets
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.collection import Collection

class AuthService:
    def __init__(self, mongo_client: MongoClient, db_name: str, config):
        self.db = mongo_client[db_name]
        self.challenges: Collection = self.db["otp_challenges"]
        self.config = config

        self._setup_indexes()

    def _setup_indexes(self):
        self.challenges.create_index("expires_at", expireAfterSeconds=0)
        self.challenges.create_index("challenge_id", unique=True)

    def _otp_hash_once(self, code: str, challenge_id: str, email: str) -> str:
        msg = f"{challenge_id}:{email}:{code}".encode()
        return hmac.new(
            self.config.OTP_SECRET_KEY.encode(),
            msg,
            hashlib.sha256
        ).hexdigest()

    def _otp_hash(self, code: str, challenge_id: str, email: str) -> str:
        """
        Aplica HMAC SHA256 iterado 1024 vezes (key stretching).
        """
        h = self._otp_hash_once(code, challenge_id, email)
        for _ in range(1023):
            h = hmac.new(
                self.config.OTP_SECRET_KEY.encode(),
                h.encode(),
                hashlib.sha256
            ).hexdigest()
        return h

    def _compare_const(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)

    def create_otp_challenge(self, email: str, ip: str) -> Optional[Dict[str, Any]]:
        self.challenges.delete_many({"email": email})
        challenge_id = secrets.token_urlsafe(16)

        # OTP mockado
        code = "123456"

        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.config.OTP_TTL_SEC)

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

        print(f"[MOCK] OTP gerado para {email}: {code}")

        return {"challenge_id": challenge_id}

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

        return {"success": True, "user_id": email}
