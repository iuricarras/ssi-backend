python3 -m venv .venv
source .venv/bin/activate
Back: FLASK_APP=app.api.main:app flask run --port 5000 --debug
Front: ng s

TESTAR AUTENTICAÇÃO FORTE: 

# 1. Email de teste
EMAIL="teste@exemplo.com"

# 2. Chave Pública (formatada para ser uma string única no JSON)
PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF185EjPUasXoUpJXQY8x0txRSbDmiiZE3cFZYjWGJ1zRUJVZLhHM4kksV97TV3ppMu5oM4dsfVO+IoPCMEPk0A==-----END PUBLIC KEY-----"

# -------------------------------------------------------------

echo "PASSO 1/3: A obter desafio (Nonce)..."

# Faz a requisição e armazena a resposta
RESPONSE=$(curl -s -X POST http://127.0.0.1:5000/api/auth/signature/start \
-H "Content-Type: application/json" \
-d '{"email": "'"$EMAIL"'"}' | tee /dev/tty)

# Extrai o Challenge ID e o Nonce da resposta JSON
CHALLENGE_ID=$(echo "$RESPONSE" | grep -o '"challenge_id": "[^"]*' | cut -d '"' -f 4)
NONCE_BASE64=$(echo "$RESPONSE" | grep -o '"nonce": "[^"]*' | cut -d '"' -f 4)

echo "---"
echo "Challenge ID: $CHALLENGE_ID"
echo "Nonce (Base64): $NONCE_BASE64"
echo "======================================================"



# ----------------------------------------------------------

echo "PASSO 2/3: A assinar o Nonce com a chave privada..."

# 1. Decodificar o Nonce (Base64 -> Bytes brutos)
echo "$NONCE_BASE64" | base64 --decode > nonce.bin

# 2. Assinar os bytes brutos do nonce (usa test_private.pem para criar signature.bin)
openssl dgst -sha256 -sign test_private.pem -out signature.bin nonce.bin

# 3. Codificar a Assinatura (Bytes brutos -> Base64, removendo newlines)
SIGNATURE_BASE64=$(base64 signature.bin | tr -d '\n')

echo "Assinatura Base64 Gerada (SIGNATURE_BASE64): $SIGNATURE_BASE64"

# ----------------------------------------------------------

echo "PASSO 3/3: A enviar a assinatura para verificação (Autenticação)..."

# Envia a requisição de verificação
curl -X POST http://127.0.0.1:5000/api/auth/signature/verify \
-H "Content-Type: application/json" \
-d "{
    \"email\": \"$EMAIL\",
    \"challenge_id\": \"$CHALLENGE_ID\",
    \"signature\": \"$SIGNATURE_BASE64\",
    \"public_key_pem\": \"$PUBLIC_KEY_PEM\"
}"
