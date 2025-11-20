import jwt
import hashlib
from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection


## Utilizar esta função para gerar a assinatura HMAC de uma mensagem
## Utilizar no retorno de todos os endpoints

class MessageAuthentication():
    def __init__(self, mongo_client: MongoClient, db_name: str):
        self.db = mongo_client[db_name]
        self.challenges: Collection = self.db["otp_challenges"]

    def _create_hmac_secret(self, userID: str) -> str:
        user = self.challenges.find_one({"email": userID}, sort=[('_id', DESCENDING)] )
        secret = f"{userID}.{user.get('code_h')}"
        h = hashlib.new('sha256')
        h.update(secret.encode('utf-8'))
        return h.hexdigest()

    def generate_hmac_signature(self, message: str, userID: str) -> str:
        hashedSecret = self._create_hmac_secret(userID)
        return jwt.encode({"message": message}, hashedSecret, algorithm="HS256")

    def verify_hmac_signature(self, encoded: str, userID: str) -> str:
        hashedSecret = self._create_hmac_secret(userID)
        decoded = jwt.decode(encoded, hashedSecret, algorithms=["HS256"])
        if "message" not in decoded:
            return False, ""
        return True, decoded["message"]