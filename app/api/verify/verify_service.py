from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
import secrets
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag

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
        O request_verification original foi movido para NotificationService
        para integrar com o fluxo de notificação.
        """
        return {'success': False, 'error': 'Endpoint desativado. Use o fluxo de notificação.', 'status': 400}


    def accept_verification(self, user_id: str, data: dict, is_notification_flow: bool = False) -> dict:
        """
        Lógica para aceitar uma verificação solicitada.
        """

        verification_id = data.get('verificationId')
        if not verification_id:
            return {'success': False, 'error': 'ID de verificação é obrigatório.', 'status': 400}

        # 1. Buscar o documento de verificação
        verification = self.verifications.find_one({'verification_id': verification_id})
        if not verification:
            return {'success': False, 'error': 'Verificação não encontrada.', 'status': 404}

        # 2. Verificações de Autorização
        if verification['verification_user_id'] != user_id:
            if not is_notification_flow:
                return {'success': False, 'error': 'Não autorizado a aceitar esta verificação.', 'status': 403}

        if verification['accepted']:
            return {'success': False, 'error': 'Verificação já foi aceita.', 'status': 400}

        master_key = data.get('masterKey')
        if not master_key:
            return {'success': False, 'error': 'Chave mestra é obrigatória.', 'status': 400}

        # 3. Buscar a carteira do utilizador alvo
        wallet = self.wallets.find_one({'user_id': user_id})
        if not wallet:
            return {'success': False, 'error': 'Carteira do utilizador não encontrada.', 'status': 404}

        # 4. Obter os dados da carteira do utilizador a verificar
        salt = wallet.get('salt')
        data_encrypted = wallet.get('data') 
        
        if not data_encrypted:
            return {'success': False, 'error': 'A carteira do utilizador está vazia.', 'status': 404}

        # DEBUG: Adicionar log para verificar o tipo de data_encrypted
        print(f"DEBUG: Tipo de data_encrypted: {type(data_encrypted)}")
        print(f"DEBUG: Valor de data_encrypted (primeiros 100 chars): {str(data_encrypted)[:100]}")

        # Verificar se os dados já estão descriptografados (dict) ou se precisam ser decifrados (string)
        try:
            if isinstance(data_encrypted, dict):
                # Os dados já estão descriptografados no MongoDB
                print("DEBUG: Dados já estão descriptografados (dict)")
                decrypted_data_json = data_encrypted
            elif isinstance(data_encrypted, str):
                # Os dados estão cifrados como string hex
                print("DEBUG: Dados estão cifrados (string), a decifrar...")
                if not salt:
                    return {'success': False, 'error': 'Salt em falta para decifrar dados.', 'status': 404}
                decrypted_data_str = self.carteira_decifra(data_encrypted, master_key, salt)
                decrypted_data_json = json.loads(decrypted_data_str)
            else:
                return {'success': False, 'error': f'Formato de dados inválido: {type(data_encrypted).__name__}', 'status': 500}
                
        except ValueError as ve:
            print(f"Erro de ValueError na decifragem: {ve}")
            return {'success': False, 'error': 'Chave Mestra inválida ou dados de carteira corrompidos.', 'status': 400}
        except Exception as e:
            print(f"Erro inesperado ao processar dados da carteira: {e}") 
            return {'success': False, 'error': 'Erro interno ao processar dados.', 'status': 500}

        # 5. Extrair os dados específicos para verificação
        verification_data_type = verification.get('verification_data_type')
        verification_data = self._get_verification_data(decrypted_data_json, verification_data_type)

        if not verification_data:
            return {'success': False, 'error': 'Dados para verificação não encontrados na carteira.', 'status': 404}    

        # 6. Cifrar os dados de verificação com a chave secreta do verificador (enc_secret)
        enc_secret = verification.get('enc_secret')
        
        try:
            verification_data_str = json.dumps(verification_data, sort_keys=True, separators=(',', ':'))
            enc_verification_data = self._encrypt_data(verification_data_str, enc_secret)
        except Exception as e:
            print(f"Erro ao cifrar dados de verificação: {e}")
            return {'success': False, 'error': 'Erro interno ao cifrar dados para o requerente.', 'status': 500}
            
        # 7. Atualizar o documento de verificação como aceite
        self.verifications.update_one({
            'verification_id': verification_id},
            {'$set': {
                'accepted': True,
                'verification_data': enc_verification_data.hex(),
                'accepted_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(hours=24), 
                'enc_secret': None
            }}
        )
        
        return {'success': True, 'message': 'Verificação aceite com sucesso.', 'status': 200}


    def _get_verification_data(self, data: dict, verification_data_type: str) -> dict:
        """
        Extrai o dado específico (personalData ou certificate) da carteira decifrada.
        """
        personal_data_list = data.get('personalData', [])
        certificates_list = data.get('certificates', [])

        # Procurar em Dados Pessoais
        for item in personal_data_list:
            if item.get('name') == verification_data_type:
                return item
        
        # Procurar em Certificados
        for cert in certificates_list:
            if cert.get('nome') == verification_data_type:
                return cert
        
        return {}


    def carteira_decifra(self, data_encrypted, master_key: str, salt: str) -> str:
        """ 
        Decifra os dados COMPACTOS da carteira (que é uma string JSON cifrada).
        """
        # CORREÇÃO: Converter data_encrypted para string se vier como bytes
        if isinstance(data_encrypted, bytes):
            try:
                data_encrypted = data_encrypted.decode('utf-8')
            except UnicodeDecodeError:
                # Se não for UTF-8, tentar converter bytes para hex
                data_encrypted = data_encrypted.hex()
        
        # Verificar se é string
        if not isinstance(data_encrypted, str):
            raise ValueError(f"O formato dos dados cifrados da carteira é inválido (tipo: {type(data_encrypted).__name__}).")
            
        # O salt é combinado com a master_key
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

        try:
            data_bytes = bytes.fromhex(data_encrypted)
            data_decrypted = decryptor.update(data_bytes) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(data_decrypted) + unpadder.finalize()
            
            data_str = data.decode('utf-8')
            return data_str
        except ValueError as e:
            raise ValueError(f"Decifragem falhou (chave mestra provavelmente incorreta): {e}")
        except Exception as e:
            raise ValueError(f"Decifragem falhou: {e}")
        

    def _encrypt_data(self, data_str: str, secret: str) -> bytes:
        """ Cifra os dados de verificação com o segredo do requerente. """
        # O secret deve ser tratado como hex string (32 bytes em hex = 64 caracteres)
        # e depois convertido para bytes
        try:
            # Se o secret for uma string hex, converte para bytes
            if len(secret) == 64:  # 32 bytes em hex
                enc_secret = bytes.fromhex(secret)
            else:
                # Se não, faz hash SHA256 para obter 32 bytes
                h = hashlib.new('sha256')
                h.update(secret.encode('utf-8'))
                enc_secret = h.digest()
        except ValueError:
            # Se fromhex falhar, faz hash
            h = hashlib.new('sha256')
            h.update(secret.encode('utf-8'))
            enc_secret = h.digest()

        # Agora enc_secret tem 32 bytes: 16 para key, 16 para IV
        enc_key = enc_secret[:16]
        enc_iv = enc_secret[16:32]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_str.encode('utf-8')) + padder.finalize()
        data_reencrypted = encryptor.update(padded_data) + encryptor.finalize()

        return data_reencrypted
    
    
    def get_verification(self, user_id: str, verification_id: str, data: dict) -> dict:
        """
        Lógica para obter uma verificação a partir do ID.
        """

        verification = self.verifications.find_one({'verification_id': verification_id})
        
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

        data_encrypted_hex = verification.get('verification_data')
        salt = verification.get('nounce')
        
        secret = f"{master_key}{salt}" 
        h = hashlib.new('sha256')
        h.update(secret.encode('utf-8'))
        secret = h.digest()
        
        key = secret[:16]
        iv = secret[16:]
        
        try:
            algorithm = algorithms.AES(key)
            mode = modes.CBC(iv)

            cipher = Cipher(algorithm, mode)
            decryptor = cipher.decryptor()  

            data_bytes = bytes.fromhex(data_encrypted_hex)
            data_decrypted = decryptor.update(data_bytes) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data_unpadded = unpadder.update(data_decrypted) + unpadder.finalize()
            
            decrypted_data_str = data_unpadded.decode('utf-8')
            decrypted_data_json = json.loads(decrypted_data_str)

        except Exception as e:
            print(f"Erro na decifra dos dados de verificação: {e}")
            return {'success': False, 'error': 'Chave Mestra inválida.', 'status': 400}
        
        
        return {
            'success': True,
            'verifications': {
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': verification['verification_data_type'],
                'verification_data': decrypted_data_json,
                'accepted_at': verification['accepted_at']
            },
            'status': 200
        }


    def get_pending_verifications(self, user_id: str) -> dict:
        """
        Lógica para obter as verificações pendentes para o utilizador atual (EC/Requerente).
        """
        pending_verifications_cursor = self.verifications.find({
            'requester_user_id': user_id,
            'accepted': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })

        pending_verifications = []
        for verification in pending_verifications_cursor:
            pending_verifications.append({
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
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
        Lógica para obter todas as verificações solicitadas pelo utilizador atual (EC/Requerente).
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

        data_bytes = bytes.fromhex(data_encrypted)
        data_decrypted = decryptor.update(data_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data_decrypted) + unpadder.finalize()
        
        data_str = data.decode('utf-8')
        return data_str

    def _rencrypt_data(self, data_str: str, master_key: str) -> tuple:
        """ Re cifra os dados da carteira com a chave mestra. """
        nounce = secrets.token_bytes(16)
        h = hashlib.new('sha256')
        h.update(f"{master_key}{nounce.hex()}".encode('utf-8'))

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

        return data_reencrypted, nounce.hex()