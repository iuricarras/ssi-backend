from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class VerifyService:
    def __init__(self, mongo_client: MongoClient, db_name: str, config): 
        self.db = mongo_client[db_name]
        self.verifications = self.db["verifications"]
        self.wallets = self.db["carteiras"]
        self.config = config

        self._setup_indexes()

    def _setup_indexes(self):
        self.verifications.create_index("verification_id", unique=True)
        self.verifications.create_index("expires_at", expireAfterSeconds=0)


    def request_verification(self, user_id: str, data: dict) -> dict:
        """
        Lógica para solicitar uma nova verificação.
        """

        master_key = data.get('masterKey')
        if not master_key:
            return {'success': False, 'error': 'Chave mestra é obrigatória.', 'status': 400}

        verification_user = data.get('verificationUser')
        if not verification_user:
            return {'success': False, 'error': 'Utilizador de verificação é obrigatório.', 'status': 400}

        verification_data_type = data.get('verificationDataType')
        if not verification_data_type:
            return {'success': False, 'error': 'Tipos de dados para verificação são obrigatórios.', 'status': 400}

        # Verificar se a carteira do utilizador existe
        carteira = self.wallets.find_one({'user_id': verification_user})
        if not carteira:
            return {'success': False, 'error': 'Carteira do utilizador de verificação não encontrada.', 'status': 404}

        nounce = Random.get_random_bytes(16)
        h = hashlib.new('sha256')
        h.update(f"{master_key}{nounce.hex()}".encode('utf-8'))

        enc_secret = h.hexdigest()
        
        expires_at = datetime.utcnow() + timedelta(hours=24)

        # Criar um novo documento de verificação
        verification_doc = {
            'verification_id': secrets.token_urlsafe(16),
            'requester_user_id': user_id,
            'verification_user_id': verification_user,
            'verification_data_type': verification_data_type,
            'enc_secret': enc_secret,
            'nounce': nounce.hex(),
            'accepted': False,
            'created_at': datetime.utcnow(),
            'expires_at': expires_at
        }

        self.verifications.insert_one(verification_doc)

        return {'success': True, 'message': 'Verificação solicitada com sucesso.', 'status': 200}

    def accept_verification(self, user_id: str, data: dict) -> dict:
        """
        Lógica para aceitar uma verificação solicitada.
        """

        # Extrair e validar os dados necessários
        verification_id = data.get('verificationId')
        if not verification_id:
            return {'success': False, 'error': 'ID de verificação é obrigatório.', 'status': 400}

        verification = self.verifications.find_one({'verification_id': verification_id})
        if not verification:
            return {'success': False, 'error': 'Verificação não encontrada.', 'status': 404}

        if verification['verification_user_id'] != user_id:
            return {'success': False, 'error': 'Não autorizado a aceitar esta verificação.', 'status': 403}

        if verification['accepted']:
            return {'success': False, 'error': 'Verificação já foi aceita.', 'status': 400}

        master_key = data.get('masterKey')
        if not master_key:
            return {'success': False, 'error': 'Chave mestra é obrigatória.', 'status': 400}

        wallet = self.wallets.find_one({'user_id': user_id})
        if not wallet:
            return {'success': False, 'error': 'Carteira do utilizador não encontrada.', 'status': 404}

        # Descifrar os dados da carteira do utilizador a verificar
        salt = wallet.get('salt')
        decrypted_data_str = self._get_encrypted_data(
            wallet.get('data_encrypted'), master_key, salt
        )
        
        # Extrair os dados específicos para verificação
        verification_data_type = verification.get('verification_data_type')

        verification_data = self._get_verification_data(decrypted_data_str, verification_data_type)

        if not verification_data:
            return {'success': False, 'error': 'Dados para verificação não encontrados na carteira.', 'status': 404}    

        # Cifrar os dados de verificação com a chave secreta do verificador
        enc_secret = verification.get('enc_secret')

        enc_verification_data = self._encrypt_data(str(verification_data), enc_secret)

        # Atualizar o documento de verificação como aceite
        self.verifications.update_one({
            'verification_id': verification_id},
            {'$set': {
                'accepted': True,
                'verification_data': enc_verification_data,
                'accepted_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(hours=24),
                'enc_secret': None
            }}
        )

        # Cifar novamente os dados da carteira do utilizador para segurança
        data_reencrypted, nounce = self._rencrypt_data(decrypted_data_str, master_key)
        self.wallets.update_one(
            {'user_id': user_id},
            {'$set': {
                'data_encrypted': data_reencrypted,
                'salt': nounce
            }}
        )


        ##ENVIAR EMAIL 

        return {'success': True, 'message': 'Verificação aceita com sucesso.', 'status': 200}


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
        
        master_key = data.get('masterKey')
        if not master_key:
            return {'success': False, 'error': 'Chave mestra é obrigatória.', 'status': 400}

        data_encrypted = verification.get('verification_data')
        salt = verification.get('nounce')

        # Descifrar os dados de verificação com a chave mestra
        decrypted_data_str = self._get_encrypted_data(
            data_encrypted, master_key, salt
        )

        return {
            'success': True,
            'verifications': {
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': verification['verification_data_type'],
                'verification_data': decrypted_data_str,
                'accepted_at': verification['accepted_at']
            },
            'status': 200
        }


    def get_pending_verifications(self, user_id: str) -> dict:
        """
        Lógica para obter as verificações pendentes para o utilizador atual.
        """

        pending_verifications_cursor = self.verifications.find({
            'verification_user_id': user_id,
            'accepted': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })

        pending_verifications = []
        for verification in pending_verifications_cursor:
            pending_verifications.append({
                'verification_id': verification['verification_id'],
                'requester_user_id': verification['requester_user_id'],
                'verification_data_type': verification['verification_data_type'],
                'created_at': verification['created_at'],
                'expires_at': verification['expires_at']
            })

        return {
            'success': True,
            'pending_verifications': pending_verifications,
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
            verifications.append({
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': verification['verification_data_type'],
                'accepted': verification['accepted'],
                'created_at': verification['created_at'],
                'expires_at': verification['expires_at']
            })

        return {
            'success': True,
            'verifications': verifications,
            'status': 200
        }


    def _get_verification_data(self, data: dict, verification_data_type: str) -> dict:

        personalData = data.get('personalData', {})
        credentials = data.get('credentials', {})

        verification_data = {}

        for item in personalData:
            if item['name'] == verification_data_type:
                verification_data.add(item)
                return verification_data
        for item in credentials:
            if item['nome'] == verification_data_type:
                verification_data.add(item)
                return verification_data

        return verification_data

    def _get_encrypted_data(self, data_encrypted: bytes, master_key: str, salt: str) -> str:
        """ Descifra os dados da carteira com a chave mestra. """
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

        data_decrypted = decryptor.update(data_encrypted) + decryptor.finalize()
        data_str = data_decrypted.decode('utf-8')
        return data_str

    def _encrypt_data(self, data_str: str, secret: str) -> tuple:
        """ Cifra os dados da carteira com a chave mestra. """
        enc_secret = secret.encode('utf-8')

        enc_key = enc_secret[:16]
        enc_iv = enc_secret[16:]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  
        data_reencrypted = encryptor.update(data_str.encode('utf-8')) + encryptor.finalize()
        return data_reencrypted

    def _rencrypt_data(self, data_str: str, master_key: str) -> tuple:
        """ Re cifra os dados da carteira com a chave mestra. """
        nounce = Random.get_random_bytes(16)
        h = hashlib.new('sha256')
        h.update(f"{master_key}{nounce.hex()}".encode('utf-8'))

        enc_secret = h.digest()

        enc_key = enc_secret[:16]
        enc_iv = enc_secret[16:]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  
        data_reencrypted = encryptor.update(data_str.encode('utf-8')) + encryptor.finalize()

        return data_reencrypted, nounce.hex()