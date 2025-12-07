from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
import secrets
import json
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Importações não utilizadas, removidas
# from cryptography.hazmat.primitives import padding # Importações não utilizadas, removidas

class VerifyService:
    def __init__(self, mongo_client: MongoClient, db_name: str, config): 
        self.db = mongo_client[db_name]
        self.verifications = self.db["verifications"]
        self.wallets = self.db["carteiras"]
        self.config = config

        self._setup_indexes()

    def _setup_indexes(self):
        self.verifications.create_index("verification_id", unique=True)
        # O índice TTL deve ser gerido pelo serviço que cria/aceita a notificação, 
        # mas mantemos aqui para verificação.
        self.verifications.create_index("expires_at", expireAfterSeconds=0)


    def create_verification_entry(self, requester_id: str, verification_user: str, verification_data_type: str, master_key: str) -> dict:
        """
        Cria a entrada inicial na coleção 'verifications' APÓS o EC ter solicitado.
        Esta entrada será atualizada quando o utilizador ACEITAR via notificação.
        Retorna o ID da verificação e a chave secreta (enc_secret) cifrada pelo EC.
        """
        # 1. Gerar Nounce e Chave Cifrada do EC (usando a masterKey fornecida pelo EC)
        nounce = secrets.token_bytes(16)
        h = hashlib.new('sha256')
        # Utilizamos a master key do EC e o nounce gerado para criar o segredo de cifra.
        h.update(f"{master_key}{nounce.hex()}".encode('utf-8'))
        enc_secret = h.hexdigest()
        
        expires_at = datetime.utcnow() + timedelta(hours=24) # Expira em 24h se não for aceite

        # 2. Criar um novo documento de verificação
        verification_doc = {
            'verification_id': secrets.token_urlsafe(16),
            'requester_user_id': requester_id,
            'verification_user_id': verification_user,
            'verification_data_type': verification_data_type,
            'enc_secret': enc_secret, # Chave do EC para cifra do dado a ser partilhado
            'nounce': nounce.hex(), # Nounce para o EC decifrar o dado.
            'accepted': False,
            'created_at': datetime.utcnow(),
            'expires_at': expires_at
        }

        self.verifications.insert_one(verification_doc)

        return {'success': True, 
                'verification_id': verification_doc['verification_id'], 
                'nounce': nounce.hex(), 
                'status': 200}
    
    
    def complete_verification(self, user_id: str, verification_id: str, user_master_key: str) -> dict:
        """
        Lógica para completar a verificação após o utilizador aceitar via notificação.
        Decifra o dado do utilizador com user_master_key, cifra com enc_secret do EC, e salva.
        """

        verification = self.verifications.find_one({'verification_id': verification_id})
        if not verification:
            return {'success': False, 'error': 'Verificação não encontrada.', 'status': 404}

        if verification['verification_user_id'] != user_id:
            return {'success': False, 'error': 'Não autorizado a completar esta verificação.', 'status': 403}

        wallet = self.wallets.find_one({'user_id': user_id})
        if not wallet:
            return {'success': False, 'error': 'Carteira do utilizador não encontrada.', 'status': 404}

        # 1. Obter e decifrar os dados da carteira do utilizador
        from cryptography.hazmat.primitives import padding # Importação local
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        try:
            # Assumindo que a carteira_service tem estes métodos helper
            decrypted_data_str = self._decrypt_wallet_data(
                wallet.get('data'), user_master_key, wallet.get('salt')
            )
            
            decrypted_data = json.loads(decrypted_data_str)
            
        except Exception as e:
            return {'success': False, 'error': 'Chave Mestra do utilizador inválida.', 'status': 400}

        # 2. Extrair os dados específicos para verificação
        verification_data_type = verification.get('verification_data_type')

        verification_data = self._get_verification_data(decrypted_data, verification_data_type)

        if not verification_data:
            return {'success': False, 'error': f'Dados para verificação ({verification_data_type}) não encontrados na carteira.', 'status': 404}    

        # 3. Cifrar os dados de verificação com a chave secreta do verificador (enc_secret)
        enc_secret = verification.get('enc_secret')
        
        # A chave do EC é um hexdigest (string), não bytes. Usamos como chave para cifra.
        enc_verification_data = self._encrypt_data(json.dumps(verification_data), enc_secret)

        # 4. Re-cifrar a carteira do utilizador (boa prática de segurança após decifra)
        data_reencrypted, new_salt = self._rencrypt_data(decrypted_data_str, user_master_key)
        self.wallets.update_one(
            {'user_id': user_id},
            {'$set': {
                'data': data_reencrypted,
                'salt': new_salt
            }}
        )

        # 5. Atualizar o documento de verificação como aceite, guardando os dados cifrados
        self.verifications.update_one({
            'verification_id': verification_id},
            {'$set': {
                'accepted': True,
                'verification_data': enc_verification_data,
                'accepted_at': datetime.utcnow(),
                # Estender o TTL para 24h após a aceitação
                'expires_at': datetime.utcnow() + timedelta(hours=24), 
                'enc_secret': None # Remove a chave secreta do EC da DB
            }}
        )

        return {'success': True, 'message': 'Verificação concluída com sucesso.', 'status': 200}


    def get_verification(self, user_id: str, verification_id: str, data: dict) -> dict:
        """
        Lógica para obter uma verificação a partir do ID.
        """

        # Buscar o documento de verificação
        verification = self.verifications.find_one({'verification_id': verification_id})
        
        # Verificar se a verificação existe, pertence ao utilizador, foi aceite e não expirou
        if not verification:
            return {'success': False, 'error': 'Verificação não encontrada.', 'status': 404}

        if verification['requester_user_id'] != user_id:
            return {'success': False, 'error': 'Não autorizado a aceder a esta verificação.', 'status': 403}

        if not verification['accepted']:
            return {'success': False, 'error': 'Verificação ainda não foi aceite.', 'status': 400}

        if verification['expires_at'] < datetime.utcnow():
            return {'success': False, 'error': 'Verificação expirou.', 'status': 400}
        
        master_key = data.get('masterKey') # Esta é a chave mestra que o EC usou no pedido
        if not master_key:
            return {'success': False, 'error': 'Chave mestra é obrigatória.', 'status': 400}

        data_encrypted = verification.get('verification_data')
        salt = verification.get('nounce') # Este é o nounce que o EC usou no pedido

        # Decifrar os dados de verificação com a chave mestra do EC
        try:
            decrypted_data_str = self._decrypt_verification_data(
                data_encrypted, master_key, salt
            )
            decrypted_data = json.loads(decrypted_data_str)
        except Exception:
            return {'success': False, 'error': 'Chave Mestra do requerente inválida para decifra.', 'status': 400}


        return {
            'success': True,
            'verification': {
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': verification['verification_data_type'],
                'verification_data': decrypted_data,
                'accepted_at': verification['accepted_at']
            },
            'status': 200
        }


    def get_all_verifications(self, user_id: str) -> dict:
        """
        Lógica para obter todas as verificações solicitadas pelo utilizador atual.
        """

        verifications_cursor = self.verifications.find({
            'requester_user_id': user_id
        })

        verifications = []
        for verification in verifications_cursor:
            # Verifica se o 'nounce' existe para ser usado na decifra no momento do get_verification
            nounce = verification.get('nounce')
            
            # Formatar a estrutura de dados a ser retornada
            data_type = verification.get('verification_data_type')
            
            # Verifica se data_type existe e é dict antes de chamar .get()
            if isinstance(data_type, dict):
                data_type_display = data_type.get('chave') or data_type.get('nome') or str(data_type)
            elif data_type is not None:
                data_type_display = str(data_type)
            else:
                data_type_display = 'Tipo desconhecido'
            
            verifications.append({
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': data_type_display,
                'accepted': verification['accepted'],
                'created_at': verification['created_at'].isoformat(),
                'expires_at': verification['expires_at'].isoformat()
            })

        return {
            'success': True,
            'verifications': verifications,
            'status': 200
        }

    # --- Métodos Auxiliares de Cifra/Decifra ---

    def _get_verification_data(self, data: dict, verification_data_type: dict) -> list:
        """ Extrai os dados solicitados da carteira decifrada. """
        
        # O verification_data_type agora é um objeto: {chave: '...', tipo: '...'}
        chave_solicitada = verification_data_type.get('chave')
        tipo_solicitado = verification_data_type.get('tipo')

        if not chave_solicitada or not tipo_solicitado:
            return []

        extracted_data = []

        if tipo_solicitado == 'personalData':
            for item in data.get('personalData', []):
                if item.get('name') == chave_solicitada:
                    # Inclui apenas o item solicitado
                    extracted_data.append(item) 
                    break # Apenas um dado pessoal pode ter este nome
        
        elif tipo_solicitado == 'certificate':
            for cert in data.get('certificates', []):
                if cert.get('nome') == chave_solicitada:
                    # Inclui o certificado completo solicitado
                    extracted_data.append(cert)
                    break 

        return extracted_data


    def _decrypt_wallet_data(self, data_encrypted: str, master_key: str, salt: str) -> str:
        """ Descifra os dados da carteira do utilizador com a chave mestra do utilizador. """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        
        secret = f"{master_key}.{salt}"
        h = hashlib.new('sha256')
        h.update(secret.encode('utf-8'))
        secret = h.digest()

        key = secret[:16]
        iv = secret[16:]

        algorithm = algorithms.AES(key)
        mode = modes.CBC(iv)

        cipher = Cipher(algorithm, mode)
        decryptor = cipher.decryptor()  

        data_bytes = bytes.fromhex(data_encrypted)
        data_decrypted = decryptor.update(data_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data_decrypted) + unpadder.finalize()
        
        data_str = data.decode('utf-8')
        return data_str

    def _decrypt_verification_data(self, data_encrypted: str, master_key: str, salt: str) -> str:
        """ Descifra os dados de verificação com a chave mestra do REQUERENTE (EC). """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        
        # A chave de cifra é o hexdigest do EC + Nounce (guardado em `nounce` no doc de verification)
        enc_secret_str = f"{master_key}{salt}"
        h = hashlib.new('sha256')
        h.update(enc_secret_str.encode('utf-8'))
        enc_secret = h.digest()

        key = enc_secret[:16]
        iv = enc_secret[16:]

        algorithm = algorithms.AES(key)
        mode = modes.CBC(iv)

        cipher = Cipher(algorithm, mode)
        decryptor = cipher.decryptor()  

        data_bytes = bytes.fromhex(data_encrypted)
        data_decrypted = decryptor.update(data_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data_decrypted) + unpadder.finalize()
        
        data_str = data.decode('utf-8')
        return data_str


    def _encrypt_data(self, data_str: str, secret_hexdigest: str) -> str:
        """ Cifra os dados da carteira com o segredo hexdigest do EC. """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        
        # O segredo é o hexdigest (string)
        enc_secret = bytes.fromhex(secret_hexdigest)

        enc_key = enc_secret[:16]
        enc_iv = enc_secret[16:]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_str.encode('utf-8')) + padder.finalize()
        data_reencrypted = encryptor.update(padded_data) + encryptor.finalize()

        return data_reencrypted.hex()

    def _rencrypt_data(self, data_str: str, master_key: str) -> tuple:
        """ Re-cifra os dados da carteira com a chave mestra do utilizador e novo nounce. """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        
        nounce = secrets.token_hex(16) # Novo salt/nounce
        
        secret = f"{master_key}.{nounce}"
        h = hashlib.new('sha256')
        h.update(secret.encode('utf-8'))
        enc_secret = h.digest()

        enc_key = enc_secret[:16]
        enc_iv = enc_secret[16:]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_str.encode('utf-8')) + padder.finalize()
        data_reencrypted = encryptor.update(padded_data) + encryptor.finalize()

        return data_reencrypted.hex(), nounce

    # Os métodos de request_verification e accept_verification são removidos daqui,
    # pois a lógica passa a ser gerida pelo NotificationService.
    # Apenas o get_verification e get_all_verifications permanecem como endpoints do EC.