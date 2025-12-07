import jwt
import hashlib
import hmac
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
import json as JSON
import datetime

## Utilizar esta função para gerar a assinatura HMAC de uma mensagem
## Utilizar no retorno de todos os endpoints

class MessageAuthentication():
    def __init__(self, mongo_client: MongoClient, db_name: str):
        self.db = mongo_client[db_name]
        self.nonces: Collection = self.db["nonces"]

    def _create_hmac_secret(self, userID: str, isEC: bool) -> str:
        user = self.nonces.find_one({"email": userID}, sort=[('_id', DESCENDING)] )
        secret = f"{userID}.{user.get('nonce')}"
        print("HMAC Secret:", secret)
        h = hashlib.new('sha256')
        h.update(secret.encode('utf-8'))
        return h.hexdigest()

    def generate_hmac_signature(self, message: dict, userID: str, isEC: bool) -> str:
        hashedSecret = self._create_hmac_secret(userID, isEC)
        print("Hashed Secret for HMAC:", hashedSecret)
        print(JSON.dumps(message, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
        h = hmac.new(hashedSecret.encode('utf-8'), JSON.dumps(message, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8'), hashlib.sha256)
        return h.hexdigest()

    def verify_hmac_signature(self, message: dict, hmac_signature: str, userID: str, isEC: bool) -> str:
        return hmac.compare_digest(hmac_signature, self.generate_hmac_signature(message, userID, isEC))