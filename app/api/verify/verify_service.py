from pymongo import MongoClient
from datetime import datetime, timedelta
import hashlib
import secrets
# Importação necessária para descriptografia e padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import json # Adicionado json para carregar a string de dados
from typing import Dict, Any, List
# Removida a importação 'from app.api.notification.notification_service import NotificationService'

class VerifyService:
    # Ajustar o construtor para aceitar o NotificationService
    # NOTA: O tipo de 'notification_service' será resolvido em tempo de execução
    def __init__(self, mongo_client: MongoClient, db_name: str, config, notification_service): 
        self.db = mongo_client[db_name]
        self.verifications = self.db["verifications"]
        self.wallets = self.db["carteiras"]
        self.config = config
        self.notification_service = notification_service # Adicionado NotificationService

        self._setup_indexes()

    def _setup_indexes(self):
        self.verifications.create_index("verification_id", unique=True)
        # Manter o expireAfterSeconds=0 desativado aqui para não apagar documentos aceites

    def request_verification(self, user_id: str, data: dict) -> dict:
        """
        Lógica para solicitar uma nova verificação.
        Cria o documento de verificação e notifica o utilizador alvo.
        """

        master_key = data.get('masterKey') # Chave do EC (requerente)
        if not master_key:
            return {'success': False, 'error': 'Chave mestra (do EC) é obrigatória.', 'status': 400}

        verification_user_email = data.get('verificationUser') # Email do Utilizador (alvo)
        if not verification_user_email:
            return {'success': False, 'error': 'Utilizador de verificação é obrigatório.', 'status': 400}

        # O item selecionado no frontend tem a chave 'chave' (para dados pessoais) ou 'nome' (para certificados)
        verification_data_object = data.get('verificationDataType')
        if not verification_data_object:
            return {'success': False, 'error': 'Tipos de dados para verificação são obrigatórios.', 'status': 400}
        
        # Determinar o nome do campo solicitado para o display
        verification_data_type_name = verification_data_object.get('chave') or verification_data_object.get('nome')

        # Verificar se a carteira do utilizador alvo existe
        # Nota: A verificação de existência da carteira será feita dentro do NotificationService para evitar duplicação.
        
        # 1. Gerar Segredo de Encriptação (Hashed EC Master Key + Nonce)
        nounce = secrets.token_bytes(16)
        h = hashlib.new('sha256')
        # A chave usada para cifrar e decifrar é o hash(EC_MasterKey + Nonce)
        h.update(f"{master_key}{nounce.hex()}".encode('utf-8')) 
        enc_secret = h.hexdigest()
        
        expires_at = datetime.utcnow() + timedelta(hours=24)

        # 2. Criar um novo documento de verificação
        verification_doc = {
            'verification_id': secrets.token_urlsafe(16),
            'requester_user_id': user_id, # EC ID
            'verification_user_id': verification_user_email, # User ID
            'verification_data_type': verification_data_object, # Objeto de dados (chave/nome)
            'enc_secret': enc_secret, # Segredo para cifrar o dado a ser visto pelo EC
            'nounce': nounce.hex(), # Nounce para o segredo
            'accepted': False,
            'created_at': datetime.utcnow(),
            'expires_at': expires_at # Este expira_at será atualizado para +24h na aceitação
        }

        try:
            self.verifications.insert_one(verification_doc)
        except Exception as e:
            return {'success': False, 'error': f'Erro ao salvar pedido de verificação: {e}', 'status': 500}


        # 3. Criar NOTIFICAÇÃO PENDENTE para o Utilizador Alvo
        notification_result = self.notification_service.request_verification_notification(
            requester_id=user_id, # EC ID
            recipient_email=verification_user_email, # User ID
            verification_id=verification_doc['verification_id'],
            verification_data_type_name=verification_data_type_name
        )

        if not notification_result['success']:
            # Se a notificação falhar, removemos o pedido de verificação, pois o user não o receberá.
            try:
                self.verifications.delete_one({'verification_id': verification_doc['verification_id']})
            except:
                pass # Ignorar erro de remoção

            return notification_result

        return {'success': True, 'message': 'Verificação solicitada com sucesso. Utilizador notificado.', 'status': 200, 'verification_id': verification_doc['verification_id']}

    def accept_verification(self, user_id: str, data: dict) -> dict:
        """
        Função desativada. A lógica de aceitação está em NotificationService.
        """
        return {'success': False, 'error': 'A aceitação deve ser feita através do endpoint de notificações.', 'status': 400}

    def get_verification(self, user_id: str, verification_id: str, data: dict) -> dict:
        """
        Lógica para obter uma verificação a partir do ID.
        Requer a chave definida pelo EC no momento do pedido.
        """

        # Buscar o documento de verificação
        verification = self.verifications.find_one({'verification_id': verification_id})
        
        # Verificar se a verificação existe, pertence ao EC requerente, foi aceite e não expirou
        if not verification:
            return {'success': False, 'error': 'Verificação não encontrada.', 'status': 404}

        if verification['requester_user_id'] != user_id:
            return {'success': False, 'error': 'Não autorizado a aceder a esta verificação.', 'status': 403}

        if not verification['accepted']:
            return {'success': False, 'error': 'Verificação ainda não foi aceite.', 'status': 400}

        if verification['expires_at'] < datetime.utcnow():
            return {'success': False, 'error': 'Verificação expirou.', 'status': 400}
        
        # A chave Mestra aqui é a chave definida pelo EC no momento do pedido (a única que funciona)
        master_key = data.get('masterKey') 
        if not master_key:
            return {'success': False, 'error': 'Chave mestra (do EC) é obrigatória.', 'status': 400}

        # O dado de verificação (já cifrado com a chave do EC) é o `verification_data`
        # O nounce para decifrar é o `nounce` (que é o nounce gerado na requisição)
        data_encrypted = verification.get('verification_data')
        salt = verification.get('nounce')
        
        # 1. Recalcular o segredo de encriptação
        h = hashlib.new('sha256')
        # hash(EC_MasterKey + Nonce)
        h.update(f"{master_key}{salt}".encode('utf-8')) 
        enc_secret_key = h.digest()
        
        # 2. Descifrar os dados de verificação com a chave do EC
        try:
            # Usar função auxiliar desta classe
            decrypted_data_str = self._decrypt_value_with_secret(
                data_encrypted, enc_secret_key
            )
        except ValueError:
            return {'success': False, 'error': 'Chave mestra (do EC) inválida ou dados corrompidos.', 'status': 400}

        # Assumindo que o dado decifrado é uma representação de lista (ex: string de lista JSON)
        try:
            # Tenta carregar como JSON
            verification_data_list = json.loads(decrypted_data_str)
            if not isinstance(verification_data_list, list):
                verification_data_list = []
        except:
             verification_data_list = []

        return {
            'success': True,
            'verification': {
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': verification['verification_data_type'],
                'verification_data': verification_data_list, # Retorna a lista de dados
                'accepted_at': verification['accepted_at']
            },
            'status': 200
        }


    def get_pending_verifications(self, user_id: str) -> dict:
        """
        Lógica para obter as verificações pendentes para o EC/requerente.
        """

        verifications_cursor = self.verifications.find({
            'requester_user_id': user_id,
            'accepted': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })
        # Os pedidos pendentes para o EC (requester) são pedidos que ainda não foram aceites pelo Utilizador
        # O EC não tem pedidos pendentes de aceitação, só pedidos PENDENTES de resposta do user.

        pending_verifications = []
        for verification in verifications_cursor:
            # CORREÇÃO CRÍTICA: Tratar o caso em que verification_data_type é uma string.
            v_data_type = verification['verification_data_type']
            if isinstance(v_data_type, dict):
                 display_name = v_data_type.get('chave') or v_data_type.get('nome') or str(v_data_type)
            else:
                 # Se for string (ou outro tipo), usamos diretamente como nome
                 display_name = str(v_data_type) 
            # FIM CORREÇÃO CRÍTICA

            pending_verifications.append({
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': display_name,
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
        Lógica para obter todas as verificações solicitadas pelo utilizador atual (EC).
        """

        verifications_cursor = self.verifications.find({
            'requester_user_id': user_id
        })

        verifications = []
        for verification in verifications_cursor:
            # CORREÇÃO CRÍTICA: Tratar o caso em que verification_data_type é uma string.
            v_data_type = verification['verification_data_type']
            if isinstance(v_data_type, dict):
                display_name = v_data_type.get('chave') or v_data_type.get('nome') or str(v_data_type)
            else:
                 # Se for string (ou outro tipo), usamos diretamente como nome
                 display_name = str(v_data_type)
            # FIM CORREÇÃO CRÍTICA
            
            verifications.append({
                'verification_id': verification['verification_id'],
                'verification_user_id': verification['verification_user_id'],
                'verification_data_type': display_name,
                'accepted': verification['accepted'],
                'created_at': verification['created_at'],
                'expires_at': verification['expires_at']
            })

        return {
            'success': True,
            'verifications': verifications,
            'status': 200
        }


    def _get_verification_data(self, data_str: str, verification_data_object: Dict[str, Any]) -> List[Dict[str, str]] | None:
        """
        Extrai o dado específico (pessoal ou certificado) do JSON da carteira decifrada.
        Retorna uma lista de objetos: [{chave: nome, valor: valor}]
        """
        try:
            # Garantir que a string de dados é carregada como JSON
            data = json.loads(data_str)
        except json.JSONDecodeError:
            return None

        personalData = data.get('personalData', [])
        credentials = data.get('certificates', []) # Nota: A sua estrutura de carteira parece usar 'certificates'

        verification_data_list = []
        
        target_name = verification_data_object.get('chave') or verification_data_object.get('nome')
        
        if not target_name:
            return None

        # 1. Procurar em Dados Pessoais
        for item in personalData:
            if item.get('name') == target_name:
                verification_data_list.append({'chave': item['name'], 'valor': item['value']})
                return verification_data_list # Dado Pessoal é um único campo

        # 2. Procurar em Certificados
        for cert in credentials:
            if cert.get('nome') == target_name:
                # Se for um certificado, retornamos todos os seus campos, exceto "nome"
                for key, value in cert.items():
                    if key != 'nome':
                         verification_data_list.append({'chave': key, 'valor': value})
                return verification_data_list # Retorna todos os campos do certificado

        return None # Não encontrado

    # Função que decifra com a chave mestra do UTILIZADOR (hash(User_MasterKey + Salt))
    # Esta função será usada pelo NotificationService.
    def _decrypt_carteira_data_hex(self, data_encrypted_hex: str, master_key: str, salt: str) -> str:
        """ 
        Descifra os dados da carteira (string hex) com a chave mestra do UTILIZADOR, 
        e retorna a string JSON decifrada.
        """
        secret = f"{master_key}.{salt}"
        h = hashlib.new('sha256')
        h.update(secret.encode('utf-8'))
        secret = h.digest() # Chave de 32 bytes

        try:
            decrypted_data_str = self._decrypt_value_with_secret(data_encrypted_hex, secret)
            # A carteira armazena JSON, então o decifrado deve ser uma string JSON
            return decrypted_data_str
        except ValueError as e:
            # Captura a falha na decifra e relança para ser tratada como 'Chave Mestra inválida'
            raise ValueError(f"Chave Mestra incorreta. {str(e)}")


    def _encrypt_data_with_secret(self, data_str: str, secret_key: bytes) -> str:
        """ 
        Cifra a string JSON de dados com uma chave secreta fornecida (hash da chave do EC).
        Retorna em formato hexadecimal.
        """
        enc_key = secret_key[:16]
        enc_iv = secret_key[16:]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_str.encode('utf-8')) + padder.finalize()
        data_reencrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return data_reencrypted.hex()

    def _decrypt_value_with_secret(self, data_encrypted_hex: str, secret_key: bytes) -> str:
        """ 
        Decifra o valor individual (string hex) com a chave secreta fornecida (hash da chave do EC ou do User).
        """
        try:
            key = secret_key[:16]
            iv = secret_key[16:]

            algorithm = algorithms.AES(key)
            mode = modes.CBC(iv)

            cipher = Cipher(algorithm, mode)
            decryptor = cipher.decryptor()  

            data_bytes = bytes.fromhex(data_encrypted_hex)
            data_decrypted = decryptor.update(data_bytes) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(data_decrypted) + unpadder.finalize()
            
            data_str = data.decode('utf-8')
            return data_str
        except Exception as e:
            # Adicionado log de erro para debug
            print(f"Erro na decifra com chave secreta: {e}")
            raise ValueError("Falha na decifra")


    def _rencrypt_data(self, data_str: str, master_key: str) -> tuple:
        """ Re-cifra os dados da carteira (string JSON) com a chave mestra do UTILIZADOR e um novo salt. """
        nounce = secrets.token_bytes(16)
        h = hashlib.new('sha256')
        # hash(User_MasterKey + Salt)
        h.update(f"{master_key}.{nounce.hex()}".encode('utf-8')) 

        enc_secret = h.digest() # Chave de 32 bytes

        enc_key = enc_secret[:16]
        enc_iv = enc_secret[16:]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  

        padder = padding.PKCS7(128).padder()
        
        # data_str é a string JSON da carteira
        padded_data = padder.update(data_str.encode('utf-8')) + padder.finalize()
        data_reencrypted = encryptor.update(padded_data) + encryptor.finalize()

        return data_reencrypted.hex(), nounce.hex()