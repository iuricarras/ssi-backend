import jwt
import hashlib
## Utilizar esta função para gerar a assinatura HMAC de uma mensagem
## Utilizar no retorno de todos os endpoints
def generate_hmac_signature(message: str, userJWT: str, userNounce: str) -> str:
    secret = f"{userJWT}.{userNounce}"
    h = hashlib.new('sha256')
    h.update(secret.encode('utf-8'))
    h.hexdigest()
    return jwt.encode({"message": message}, h.hexdigest(), algorithm="HS256")
