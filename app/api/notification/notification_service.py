from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from datetime import datetime, timedelta
from typing import Dict, Any, List
import secrets
<<<<<<< Updated upstream
import json
import base64
from app.services.email_service import EmailService
from app.api.carteira.carteira_service import CarteiraService

from app.services.email_service import EmailService
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
=======
import hashlib
import json
from cryptography.hazmat.primitives import hashes 

from app.services.email_service import EmailService
from app.api.carteira.carteira_service import CarteiraService 
from app.api.verify.verify_service import VerifyService # Importar VerifyService
>>>>>>> Stashed changes

class NotificationService:
    """
    Serviço responsável pela gestão de notificações e requisições pendentes
    (e.g., pedidos de certificado, pedidos de verificação de dados).
    """
    def __init__(self, mongo_client: MongoClient, db_name: str, mail_service: EmailService, carteira_service: CarteiraService, verify_service: VerifyService, config: Dict):
        self.db = mongo_client[db_name]
        self.notifications: Collection = self.db["notifications"]
        self.users: Collection = self.db["user"]
        self.wallets = self.db["carteiras"]
        self.verifications = self.db["verifications"] # Nova coleção
        self.mail_service = mail_service
        self.carteira_service = carteira_service # Injeção do serviço
        self.verify_service = verify_service # NOVO: Injeção do VerifyService
        self.config = config
        
        self._setup_indexes()

    def _setup_indexes(self):
        self.notifications.create_index("recipient_user_id")
        self.notifications.create_index("status")
        self.notifications.create_index([("recipient_user_id", DESCENDING), ("status", DESCENDING)])
        # NOVO: Indices para a colecção de verificações, se ainda não estiverem no VerifyService
        self.verifications.create_index("verification_id", unique=True)
        self.verifications.create_index("expires_at", expireAfterSeconds=0)
        self.verifications.create_index("verification_user_id") # Para que o EC consiga ver os pedidos feitos a ele
        self.verifications.create_index("requester_user_id") # Para que o utilizador consiga ver os pedidos feitos por ele


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
    
    # NOVO MÉTODO PARA PEDIR INFORMAÇÃO
    def request_verification_data(self, requester_id: str, recipient_email: str, master_key: str, verification_data_type: str) -> Dict[str, Any]:
        """
        Inicia o processo de pedido de verificação de dados.
        Cria uma notificação pendente para o utilizador e um documento de verificação na DB.
        """
        recipient_user = self._get_user_info(recipient_email)
        requester_user = self._get_user_info(requester_id)

        if not recipient_user:
            return {"success": False, "error": "O utilizador destinatário não foi encontrado.", "status": 404}
        if not requester_user:
            return {"success": False, "error": "A Entidade Requerente não foi encontrada.", "status": 403}

        # 1. Buscar a carteira do utilizador alvo
        carteira = self.wallets.find_one({'user_id': recipient_email})
        if not carteira:
            return {'success': False, 'error': 'Carteira do utilizador de verificação não encontrada.', 'status': 404}


        # 2. Gerar nounce e enc_secret usando a master_key do REQUERENTE (EC)
        nounce_bytes = secrets.token_bytes(16)
        h = hashlib.new('sha256')
        h.update(f"{master_key}{nounce_bytes.hex()}".encode('utf-8'))
        enc_secret = h.hexdigest()
        
        expires_at = datetime.utcnow() + timedelta(hours=24) # Expira em 24h

        # 3. Criar Documento de Verificação (para a EC ver o estado)
        verification_doc = {
            'verification_id': secrets.token_urlsafe(16),
            'requester_user_id': requester_id, # EC (quem está a pedir)
            'verification_user_id': recipient_email, # Utilizador Alvo (quem tem os dados)
            'verification_data_type': verification_data_type, # Dado/Certificado pedido
            'enc_secret': enc_secret, # Segredo para cifrar o dado se o user aceitar
            'nounce': nounce_bytes.hex(), # Nounce para o segredo
            'accepted': False,
            'created_at': datetime.utcnow(),
            'expires_at': expires_at
        }
        
        try:
            self.verifications.insert_one(verification_doc)
        except Exception as e:
            print(f"Erro ao inserir documento de verificação: {e}")
            return {"success": False, "error": "Erro interno ao criar pedido de verificação.", "status": 500}


        # 4. Criar Notificação para o utilizador alvo
        notification_doc = {
            "notification_id": secrets.token_urlsafe(16),
            "recipient_user_id": recipient_email, # <-- Utilizador Alvo (quem vai receber a notificação)
            "requester_id": requester_id,
            "type": "VERIFICATION_REQUEST",
            "status": "PENDING", 
            "payload": {
                "verification_id": verification_doc['verification_id'],
                "verification_data_type": verification_data_type
            },
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        try:
            self.notifications.insert_one(notification_doc)
            
            user_name = recipient_user.get("nome", recipient_email)
            requester_name = requester_user.get("nome", requester_id)
            
            # 5. Enviar Email
            request_type_display = f"Pedido de Verificação de Dados ({verification_data_type})"
            email_html = self.mail_service.create_new_request_html(
                user_name=user_name,
                requester_name=requester_name,
                request_type=request_type_display
            )
            self.mail_service.send_notification_email(
                recipient_email=recipient_email,
                subject="[BitsOfMe] Novo Pedido de Verificação Pendente",
                content_html=email_html
            )

            return {"success": True, "message": "Pedido de verificação submetido e notificação enviada.", "status": 200, "notification_id": notification_doc["notification_id"]}
        
        except Exception as e:
            print(f"Erro ao inserir notificação: {e}")
            # Se falhar a notificação, apagar o documento de verificação criado
            self.verifications.delete_one({"verification_id": verification_doc['verification_id']})
            return {"success": False, "error": "Erro interno ao processar a requisição.", "status": 500}


    def get_pending_notifications(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Retorna todas as notificações pendentes para o utilizador.
        """
        projection = {
            "_id": 0,
            "notification_id": 1,
            "requester_id": 1,
            "type": 1,
            "payload.certificate_name": 1,
            "payload.verification_id": 1, # NOVO
            "payload.verification_data_type": 1, # NOVO
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
<<<<<<< Updated upstream

        for notif in notifications:
            if isinstance(notif.get('created_at'), datetime):
                notif['created_at'] = notif['created_at'].isoformat()

=======
            
            # NOVO: Formatacao de payload para VERIFICATION_REQUEST
            if notif['type'] == 'VERIFICATION_REQUEST' and 'payload' in notif:
                # verification_data_type é a string do campo/nome do certificado
                data_type = notif['payload'].get('verification_data_type', 'Dado Desconhecido')
                # A API Frontend precisa do nome do campo na raiz do payload.
                notif['payload']['verification_data_type_display'] = data_type
                    
>>>>>>> Stashed changes
        return notifications


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
            
            # Se for pedido de verificação, apagar o documento de verificação
            if notification['type'] == "VERIFICATION_REQUEST":
                 verification_id = notification['payload'].get('verification_id')
                 if verification_id:
                    self.verifications.delete_one({"verification_id": verification_id})

            self.notifications.update_one(
                {"notification_id": notification_id},
                {"$set": {"status": "REJECTED", "updated_at": datetime.utcnow()}}
            )
            return {"success": True, "message": "Requisição recusada com sucesso.", "status": 200}
        
        elif action == "ACCEPT":
            if not master_key:
                return {"success": False, "error": "A Chave Mestra é obrigatória para aceitar esta requisição.", "status": 400}

            if notification['type'] == "CERTIFICATE_ADDITION":
                try:
                    certificate_data = notification['payload']['data']                    
                    if not self.carteira_service.add_certificate(user_id, certificate_data, master_key):
                        return {"success": False, "error": "Falha ao adicionar certificado (DB error).", "status": 500}

                except ValueError as ve:
                    return {"success": False, "error": f"Falha ao adicionar certificado: {str(ve)}", "status": 400}
                except Exception as e:
                    print(f"Erro inesperado na adição do certificado: {e}")
                    return {"success": False, "error": "Erro interno do servidor ao processar certificado.", "status": 500}

                self.notifications.update_one(
                    {"notification_id": notification_id},
                    {"$set": {"status": "ACCEPTED", "updated_at": datetime.utcnow()}}
                )
                return {"success": True, "message": "Certificado adicionado à sua carteira.", "status": 200}

            # NOVO: Lógica para aceitar Pedido de Verificação de Dados
            elif notification['type'] == "VERIFICATION_REQUEST":
                verification_id = notification['payload'].get('verification_id')
                if not verification_id:
                    return {"success": False, "error": "ID de verificação em falta no payload.", "status": 400}

                # Chamar a lógica de aceitação do VerifyService, que lida com a criptografia
                # e atualização do documento 'verifications'.
                result = self.verify_service.accept_verification(
                    user_id=user_id, # utilizador alvo
                    data={
                        'verificationId': verification_id,
                        'masterKey': master_key
                    },
                    is_notification_flow=True # Flag para indicar que o fluxo é via notificação
                )
                
                if not result['success']:
                    # O VerifyService retorna mensagens de erro detalhadas
                    return {"success": False, "error": result['error'], "status": result['status']}


                self.notifications.update_one(
                    {"notification_id": notification_id},
                    {"$set": {"status": "ACCEPTED", "updated_at": datetime.utcnow()}}
                )
                return {"success": True, "message": "Pedido de verificação aceite. A Entidade Requerente foi notificada.", "status": 200}

            else:
                return {"success": False, "error": "Tipo de notificação desconhecido para aceitação.", "status": 400}
            
        else:
            return {"success": False, "error": "Ação inválida. Use 'ACCEPT' ou 'REJECT'.", "status": 400}

    def recreate_json_exact(self, certificate_data: dict) -> bytes:
        cert = {k: v for k, v in certificate_data.items() if k != "signature"}
        json_str = json.dumps(cert, indent=2, ensure_ascii=False)
        return json_str.encode("utf-8")


    def verify_rsa_signature_pkcs1(self, public_key_pem: str, message_bytes: bytes, signature_b64: str) -> bool:
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            signature = base64.b64decode(signature_b64)

            public_key.verify(
                signature,
                message_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True

        except Exception as e:
            print("Erro validação RSA:", e)
            return False


    def verify_certificate_signature(self, requester_id: str, certificate_data: dict) -> (bool, str):
        signature_b64 = certificate_data.get("signature")

        if not signature_b64:
            return False, "O certificado enviado não contém uma assinatura."

        entity = self.users.find_one({"email": requester_id})
        if not entity:
            return False, "Entidade certificadora não encontrada."

        public_key_pem = entity.get("signkey")
        if not public_key_pem:
            return False, "A entidade certificadora não possui chave pública registrada."

        message_bytes = self.recreate_json_exact(certificate_data)

        ok = self.verify_rsa_signature_pkcs1(public_key_pem, message_bytes, signature_b64)

        if not ok:
            return False, "Assinatura digital inválida."

        return True, None
