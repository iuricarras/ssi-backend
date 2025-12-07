from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from datetime import datetime, timedelta
from typing import Dict, Any, List
import secrets
import json # Adicionado json para converter a string de dados
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from app.services.email_service import EmailService
from app.api.carteira.carteira_service import CarteiraService 
# REMOVIDA A IMPORTAÇÃO DE 'from app.api.verify.verify_service import VerifyService' (Para evitar a circularidade)

# Funções auxiliares copiadas do VerifyService para quebrar a circularidade
# Se o CarteiraService já tem a função de decifração, não precisamos dela aqui.
# No entanto, a lógica para CIFRAR COM A CHAVE DO EC (passo 3) ainda reside no VerifyService.
# Moveremos APENAS as funções essenciais de criptografia para esta classe.

def _decrypt_value_with_secret_static(data_encrypted_hex: str, secret_key: bytes) -> str:
    """ 
    Decifra o valor individual (string hex) com a chave secreta fornecida (hash da chave do EC ou do User).
    COPIA ESTATICA do VerifyService para quebrar a circularidade.
    """
    if not isinstance(data_encrypted_hex, str):
         # Adicionado para evitar erro 'fromhex() argument must be str, not dict' se o valor for um dict/None
        raise ValueError("Dados cifrados inválidos (não é uma string hexadecimal).")
        
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
        print(f"Erro na decifra com chave secreta: {e}")
        # Relançamos ValueError para ser capturado no respond_to_notification
        raise ValueError("Falha na decifra")

def _encrypt_data_with_secret_static(data_str: str, secret_key: bytes) -> str:
    """ 
    Cifra a string JSON de dados com uma chave secreta fornecida (hash da chave do EC).
    COPIA ESTATICA do VerifyService para quebrar a circularidade.
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

# A função de decifração da carteira completa (que chama a função de cima) deve estar no CarteiraService.
# Precisamos de uma função para extrair o dado, mas como a carteira decifrada é um dicionário, 
# podemos copiar a lógica de extração para aqui também, simplificando.

def _get_verification_data_static(data: dict, verification_data_object: Dict[str, Any]) -> List[Dict[str, str]] | None:
    """
    Extrai o dado específico (pessoal ou certificado) do dicionário da carteira decifrada.
    COPIA ESTATICA do VerifyService para quebrar a circularidade.
    """

    personalData = data.get('personalData', [])
    credentials = data.get('certificates', []) 

    verification_data_list = []
    
    target_name = verification_data_object.get('chave') or verification_data_object.get('nome')
    
    if not target_name:
        return None

    for item in personalData:
        if item.get('name') == target_name:
            verification_data_list.append({'chave': item['name'], 'valor': item['value']})
            return verification_data_list 

    for cert in credentials:
        if cert.get('nome') == target_name:
            for key, value in cert.items():
                if key != 'nome':
                     verification_data_list.append({'chave': key, 'valor': value})
            return verification_data_list 

    return None

def _rencrypt_data_static(data_str: str, master_key: str, mongo_client, db_name) -> tuple:
    """ Re-cifra os dados da carteira (string JSON) com a chave mestra do UTILIZADOR e um novo salt.
    COPIA ESTATICA do VerifyService para quebrar a circularidade.
    """
    # A db não é usada aqui, mas mantemos o formato da assinatura para consistência
    
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

class NotificationService:
    """
    Serviço responsável pela gestão de notificações e requisições pendentes
    (e.g., pedidos de certificado, pedidos de verificação de dados).
    """
    def __init__(self, mongo_client: MongoClient, db_name: str, mail_service: EmailService, carteira_service: CarteiraService, config: Dict):
        self.db = mongo_client[db_name]
        self.notifications: Collection = self.db["notifications"]
        self.users: Collection = self.db["user"]
        self.verifications: Collection = self.db["verifications"] # Para aceder diretamente aos pedidos
        self.mail_service = mail_service
        self.carteira_service = carteira_service 
        self.config = config
        
        self._setup_indexes()

    def _setup_indexes(self):
        self.notifications.create_index("recipient_user_id")
        self.notifications.create_index("status")
        self.notifications.create_index([("recipient_user_id", DESCENDING), ("status", DESCENDING)])


    def _get_user_info(self, user_id: str) -> Dict[str, str] | None:
        """ Obtém nome e email do utilizador pelo seu ID (email). """
        user = self.users.find_one({"email": user_id}, {"nome": 1, "email": 1, "_id": 0})
        return user

    def request_certificate_addition(self, requester_id: str, recipient_email: str, certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inicia o processo de adição de um novo certificado à carteira de um utilizador.
        Cria uma notificação pendente e envia um email.
        """
        recipient_user = self._get_user_info(recipient_email)
        requester_user = self._get_user_info(requester_id)

        if not recipient_user:
            return {"success": False, "error": "O utilizador destinatário não foi encontrado.", "status": 404}
        if not requester_user:
            return {"success": False, "error": "A Entidade Certificadora não foi encontrada.", "status": 403}

        notification_doc = {
            "notification_id": secrets.token_urlsafe(16),
            "recipient_user_id": recipient_email,
            "requester_id": requester_id,
            "type": "CERTIFICATE_ADDITION",
            "status": "PENDING", 
            "payload": {
                "certificate_name": certificate_data.get('nome', 'Certificado Desconhecido'),
                "data": certificate_data
            },
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        try:
            self.notifications.insert_one(notification_doc)
            
            user_name = recipient_user.get("nome", recipient_email)
            requester_name = requester_user.get("nome", requester_id)
            
            email_html = self.mail_service.create_new_request_html(
                user_name=user_name,
                requester_name=requester_name,
                request_type=f"Adição de Certificado ({notification_doc['payload']['certificate_name']})"
            )
            self.mail_service.send_notification_email(
                recipient_email=recipient_email,
                subject="[BitsOfMe] Nova Requisição Pendente na sua Carteira",
                content_html=email_html
            )

            return {"success": True, "message": "Requisição submetida e notificação enviada.", "status": 200, "notification_id": notification_doc["notification_id"]}
        
        except Exception as e:
            print(f"Erro ao inserir notificação: {e}")
            return {"success": False, "error": "Erro interno ao processar a requisição.", "status": 500}
            
    def request_verification_notification(self, requester_id: str, recipient_email: str, verification_id: str, verification_data_type_name: str) -> Dict[str, Any]:
        """
        Cria a notificação pendente para um pedido de verificação de dados já registado no VerifyService.
        """
        recipient_user = self._get_user_info(recipient_email)
        requester_user = self._get_user_info(requester_id)

        if not recipient_user:
            return {"success": False, "error": "O utilizador destinatário não foi encontrado.", "status": 404}
        if not requester_user:
            return {"success": False, "error": "A Entidade Requerente não foi encontrada.", "status": 403}
        
        # O payload armazena o ID da verificação para que a resposta possa encontrá-la.
        notification_doc = {
            "notification_id": secrets.token_urlsafe(16),
            "recipient_user_id": recipient_email,
            "requester_id": requester_id,
            "type": "VERIFICATION_REQUEST", # Novo tipo
            "status": "PENDING", 
            "payload": {
                "verification_id": verification_id,
                "data_type_name": verification_data_type_name
            },
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        
        try:
            self.notifications.insert_one(notification_doc)
            
            user_name = recipient_user.get("nome", recipient_email)
            requester_name = requester_user.get("nome", requester_id)
            
            email_html = self.mail_service.create_new_request_html(
                user_name=user_name,
                requester_name=requester_name,
                request_type=f"Verificação de Dados ({verification_data_type_name})"
            )
            self.mail_service.send_notification_email(
                recipient_email=recipient_email,
                subject="[BitsOfMe] Nova Requisição Pendente na sua Carteira",
                content_html=email_html
            )
            
            return {"success": True, "message": "Notificação de verificação criada.", "status": 200}
        
        except Exception as e:
            print(f"Erro ao inserir notificação de verificação: {e}")
            return {"success": False, "error": "Erro interno ao processar a notificação de verificação.", "status": 500}


    def get_pending_notifications(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Retorna todas as notificações pendentes para o utilizador.
        Inclui notificação de certificado e de verificação de dados.
        """
        projection = {
            "_id": 0,
            "notification_id": 1,
            "requester_id": 1,
            "type": 1,
            "payload": 1, # Incluímos o payload completo para VERIFICATION_REQUEST
            "created_at": 1,
            "status": 1
        }
        
        pending_cursor = self.notifications.find({
            "recipient_user_id": user_id,
            "status": "PENDING"
        }, projection=projection).sort("created_at", DESCENDING)

        notifications = list(pending_cursor)
        
        for notif in notifications:
            requester_info = self._get_user_info(notif.get('requester_id'))
            notif['requester_name'] = requester_info.get('nome', notif.get('requester_id'))
            
            # Adicionar nome de display para verificação de dados
            if notif['type'] == 'VERIFICATION_REQUEST':
                # Usa o campo 'data_type_name' que guardamos no payload
                notif['payload']['certificate_name'] = notif['payload'].get('data_type_name', 'Dados Pessoais') 

        return notifications
    
    # --- FUNÇÃO AUXILIAR PARA DECIFRAR A CARTEIRA USANDO O CARTEIRASERVICE ---
    def _decrypt_full_carteira(self, user_id: str, master_key: str) -> str:
        """
        Tenta decifrar a carteira completa usando o CarteiraService.
        Se for bem-sucedido, retorna a string JSON decifrada.
        Se a chave for inválida, lança ValueError.
        """

        carteira_doc = self.db['carteiras'].find_one({'user_id': user_id})
        if not carteira_doc:
            raise ValueError("Carteira vazia ou não inicializada.")

        salt = carteira_doc.get('salt')
        data_stored = carteira_doc.get('data')

        if not data_stored or not salt:
             return json.dumps({"personalData": [], "certificates": []})

        secret = f"{master_key}.{salt}"
        h = hashlib.new('sha256')
        h.update(secret.encode('utf-8'))
        secret_bytes = h.digest() # Chave de 32 bytes
        
        # O data_stored é um dict: {personalData: [...], certificates: [...]}

        try:
            # Decifra os valores individuais no dicionário
            decrypted_data_dict = {
                "personalData": [{
                    'name': item.get('name'),
                    # Verificação para evitar decifrar valores nulos ou não strings
                    'value': _decrypt_value_with_secret_static(item.get('value'), secret_bytes)
                             if item.get('value') and isinstance(item.get('value'), str) else item.get('value')
                } for item in data_stored.get('personalData', [])
                ],
                "certificates": [{
                    k: (_decrypt_value_with_secret_static(v, secret_bytes) 
                        if k != 'nome' and v and isinstance(v, str) else v)
                    for k, v in cert.items()
                }for cert in data_stored.get('certificates', [])
                ]
            }

            # Retorna o dict decifrado como string JSON
            return json.dumps(decrypted_data_dict)
            
        except ValueError as e:
            # _decrypt_value_with_secret_static lança ValueError se a chave estiver errada
            raise ValueError(f"Chave Mestra incorreta. {e}")
        except Exception as e:
            raise Exception(f"Erro ao processar estrutura da carteira: {e}")

    # --- FIM FUNÇÕES AUXILIARES ---

    def respond_to_notification(self, user_id: str, notification_id: str, action: str, master_key: str = None) -> Dict[str, Any]:
        """
        O utilizador responde a uma notificação (Aceitar ou Recusar).
        
        """
        
        notification = self.notifications.find_one({"notification_id": notification_id})

        if not notification:
            return {"success": False, "error": "Notificação não encontrada.", "status": 404}
        
        if notification['recipient_user_id'] != user_id:
            return {"success": False, "error": "Não autorizado a responder a esta notificação.", "status": 403}
            
        if notification['status'] != "PENDING":
            return {"success": False, "error": f"Requisição já foi {notification['status'].lower()}.", "status": 400}

        
        if action == "REJECT":
            # Se for pedido de verificação, também marcamos o pedido no VerifyService como recusado/expirado
            if notification['type'] == 'VERIFICATION_REQUEST':
                verification_id = notification['payload'].get('verification_id')
                if verification_id:
                    self.verifications.update_one(
                        {'verification_id': verification_id},
                        {'$set': {'accepted': False, 'expires_at': datetime.utcnow()}}
                    )

            self.notifications.update_one(
                {"notification_id": notification_id},
                {"$set": {"status": "REJECTED", "updated_at": datetime.utcnow()}}
            )
            return {"success": True, "message": "Requisição recusada com sucesso.", "status": 200}
        
        elif action == "ACCEPT":
            if not master_key:
                 return {"success": False, "error": "A chave mestra do utilizador é obrigatória para aceitar requisições.", "status": 400}

            if notification['type'] == "CERTIFICATE_ADDITION":
                
                try:
                    certificate_data = notification['payload']['data']                    
                    if not self.carteira_service.add_certificate(user_id, certificate_data, master_key):
                        return {"success": False, "error": "Falha ao adicionar certificado (DB error).", "status": 500}

                except ValueError as ve:
                    # Captura o erro da Chave Mestra incorreta
                    return {"success": False, "error": f"Falha ao adicionar certificado: {str(ve)}", "status": 400}
                except Exception as e:
                    print(f"Erro inesperado na adição do certificado: {e}")
                    return {"success": False, "error": "Erro interno do servidor ao processar certificado.", "status": 500}

                self.notifications.update_one(
                    {"notification_id": notification_id},
                    {"$set": {"status": "ACCEPTED", "updated_at": datetime.utcnow()}}
                )
                return {"success": True, "message": "Certificado adicionado à sua carteira.", "status": 200}
            
            elif notification['type'] == 'VERIFICATION_REQUEST':
                # --- LÓGICA DE ACEITAÇÃO DE PEDIDO DE VERIFICAÇÃO ---
                
                verification_id = notification['payload'].get('verification_id')
                if not verification_id:
                     return {"success": False, "error": "ID de verificação ausente na notificação.", "status": 400}
                
                verification = self.verifications.find_one({'verification_id': verification_id})
                if not verification:
                    return {"success": False, "error": "Pedido de verificação não encontrado.", "status": 404}

                # 1. Decifrar os dados da carteira do utilizador com a sua chave mestra
                try:
                    # Chamar a função local _decrypt_full_carteira
                    decrypted_carteira_data_str = self._decrypt_full_carteira(user_id, master_key)
                    # O retorno é uma STRING JSON da carteira decifrada
                    decrypted_carteira_data_dict = json.loads(decrypted_carteira_data_str)
                    
                except ValueError as ve:
                    # Captura o erro da chave mestra do utilizador (inclui a falha na decifra)
                    print(f"Chave Mestra Inválida: {ve}")
                    return {"success": False, "error": f"Chave Mestra do utilizador inválida.", "status": 400}
                except Exception as e:
                    # Esta exceção geral é para erros inesperados
                    print(f"Erro ao decifrar carteira: {e}")
                    return {"success": False, "error": "Erro interno ao decifrar carteira.", "status": 500}

                # 2. Extrair o dado solicitado
                verification_data_object = verification.get('verification_data_type')
                # Usar a função estática de extração com o dicionário da carteira decifrada
                verification_data_list = _get_verification_data_static(
                    decrypted_carteira_data_dict, verification_data_object
                )
                
                if not verification_data_list:
                    return {"success": False, "error": "Dados para verificação não encontrados na carteira.", "status": 404}
                
                # Converter a lista de dados (chave:valor) para string JSON (para cifragem)
                try:
                    verification_data_json_str = json.dumps(verification_data_list)
                except Exception:
                    verification_data_json_str = str(verification_data_list) 


                # 3. Cifrar o dado solicitado com a chave secreta do EC
                enc_secret_key_hex = verification.get('enc_secret')
                
                # O enc_secret_key_hex já é o hash da chave do EC + nounce, mas está em hex.
                enc_secret_bytes = bytes.fromhex(enc_secret_key_hex)
                
                # Usar a função estática de cifragem com a chave do EC
                enc_verification_data_hex = _encrypt_data_with_secret_static(
                    verification_data_json_str, enc_secret_bytes
                )
                
                # 4. Atualizar o documento de verificação
                self.verifications.update_one({
                    'verification_id': verification_id},
                    {'$set': {
                        'accepted': True,
                        'verification_data': enc_verification_data_hex, # Dado cifrado com a chave do EC
                        'accepted_at': datetime.utcnow(),
                        'expires_at': datetime.utcnow() + timedelta(hours=24), # Estender validade
                        'nounce': verification.get('nounce') # Mantemos o nounce original para a decifra do EC
                    }}
                )
                
                # 5. Re-cifrar a carteira do utilizador com a sua Master Key (para garantir a segurança)
                data_reencrypted_hex, new_salt = _rencrypt_data_static(
                    decrypted_carteira_data_str, 
                    master_key, 
                    self.db.client, 
                    self.db.name # Passar referências do DB
                )
                
                self.db['carteiras'].update_one(
                    {'user_id': user_id},
                    {'$set': {
                        'data': data_reencrypted_hex,
                        'salt': new_salt
                    }}
                )

                # 6. Marcar notificação como aceite
                self.notifications.update_one(
                    {"notification_id": notification_id},
                    {"$set": {"status": "ACCEPTED", "updated_at": datetime.utcnow()}}
                )

                return {"success": True, "message": "Pedido de verificação aceite e dados partilhados.", "status": 200}
                # --- FIM LÓGICA DE ACEITAÇÃO DE PEDIDO DE VERIFICAÇÃO ---

            else:
                return {"success": False, "error": "Tipo de notificação desconhecido para aceitação.", "status": 400}
            
        else:
            return {"success": False, "error": "Ação inválida. Use 'ACCEPT' ou 'REJECT'.", "status": 400}