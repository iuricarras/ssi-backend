from pymongo import MongoClient, DESCENDING
from pymongo.collection import Collection
from datetime import datetime, timedelta
from typing import Dict, Any, List
import secrets
import json
import base64
from app.services.email_service import EmailService
from app.api.carteira.carteira_service import CarteiraService
from app.api.verify.verify_service import VerifyService # Importação adicionada

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class NotificationService:
    """
    Serviço responsável pela gestão de notificações e requisições pendentes
    (e.g., pedidos de certificado, pedidos de verificação de dados).
    """
    def __init__(self, mongo_client: MongoClient, db_name: str, mail_service: EmailService, carteira_service: CarteiraService, config: Dict, verify_service: VerifyService):
        self.db = mongo_client[db_name]
        self.notifications: Collection = self.db["notifications"]
        self.users: Collection = self.db["user"]
        self.mail_service = mail_service
        self.carteira_service = carteira_service 
        self.verify_service = verify_service # Injeção adicionada
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

    
    def request_verification_data(self, requester_id: str, recipient_email: str, master_key: str, verification_data_type: Dict[str, str]) -> Dict[str, Any]:
        """
        Inicia o processo de pedido de informação/verificação a um utilizador.
        Cria a entrada na tabela de 'verifications' E a notificação pendente.
        """
        recipient_user = self._get_user_info(recipient_email)
        requester_user = self._get_user_info(requester_id)

        if not recipient_user:
            return {"success": False, "error": "O utilizador destinatário não foi encontrado.", "status": 404}
        if not requester_user:
            return {"success": False, "error": "A Entidade Requerente não foi encontrada.", "status": 403}

        # 1. Cria a entrada inicial na coleção 'verifications'
        verification_entry = self.verify_service.create_verification_entry(
            requester_id, 
            recipient_email, 
            verification_data_type, 
            master_key
        )
        if not verification_entry['success']:
             return {"success": False, "error": "Erro interno ao criar entrada de verificação.", "status": 500}
        
        # Formatar nome do dado solicitado
        data_type_name = verification_data_type.get('chave') or verification_data_type.get('nome') or 'Dados'
        
        # 2. Cria a notificação
        notification_doc = {
            "notification_id": secrets.token_urlsafe(16),
            "recipient_user_id": recipient_email,
            "requester_id": requester_id,
            "type": "VERIFICATION_REQUEST",
            "status": "PENDING", 
            "payload": {
                "verification_id": verification_entry['verification_id'],
                "verification_type": data_type_name,
                "data_type_info": verification_data_type
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
                request_type=f"Pedido de Informação ({data_type_name})"
            )
            self.mail_service.send_notification_email(
                recipient_email=recipient_email,
                subject="[BitsOfMe] Nova Requisição Pendente na sua Carteira",
                content_html=email_html
            )

            return {"success": True, "message": "Pedido de informação submetido e notificação enviada.", "status": 200, "notification_id": notification_doc["notification_id"]}
        
        except Exception as e:
            print(f"Erro ao inserir notificação: {e}")
            return {"success": False, "error": "Erro interno ao processar a requisição de verificação.", "status": 500}
        
        
    def get_pending_notifications(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Retorna todas as notificações pendentes para o utilizador.
        """
        projection = {
            "_id": 0,
            "notification_id": 1,
            "requester_id": 1,
            "type": 1,
            "payload": 1, # Precisa do payload completo agora
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

        for notif in notifications:
            if isinstance(notif.get('created_at'), datetime):
                notif['created_at'] = notif['created_at'].isoformat()

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
            # Para pedidos de verificação, removemos a entrada na tabela de verificação
            if notification['type'] == "VERIFICATION_REQUEST":
                verification_id = notification['payload'].get('verification_id')
                if verification_id:
                     self.verify_service.verifications.delete_one({'verification_id': verification_id})

            self.notifications.update_one(
                {"notification_id": notification_id},
                {"$set": {"status": "REJECTED", "updated_at": datetime.utcnow()}}
            )
            return {"success": True, "message": "Requisição recusada com sucesso.", "status": 200}
        
        elif action == "ACCEPT":
            if not master_key:
                return {"success": False, "error": "A chave mestra é obrigatória para aceitar esta requisição.", "status": 400}

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

            
            elif notification['type'] == "VERIFICATION_REQUEST":
                verification_id = notification['payload'].get('verification_id')
                if not verification_id:
                    return {"success": False, "error": "ID de verificação em falta.", "status": 400}
                
                try:
                    # O serviço de verificação agora faz a decifra/recifra da carteira e salva o dado
                    result = self.verify_service.complete_verification(user_id, verification_id, master_key)
                    
                    if not result['success']:
                        return result
                        
                except Exception as e:
                    print(f"Erro inesperado ao completar verificação: {e}")
                    return {"success": False, "error": "Erro interno do servidor ao processar verificação.", "status": 500}

                self.notifications.update_one(
                    {"notification_id": notification_id},
                    {"$set": {"status": "ACCEPTED", "updated_at": datetime.utcnow()}}
                )
                return {"success": True, "message": "Pedido de verificação aceite e dados partilhados.", "status": 200}

            return {"success": False, "error": "Tipo de notificação desconhecido para aceitação.", "status": 400}
            
        else:
            return {"success": False, "error": "Ação inválida. Use 'ACCEPT' ou 'REJECT'.", "status": 400}

    def recreate_json_exact(self, certificate_data: dict) -> bytes:
        # ... (Mantido o código existente)
        cert = {k: v for k, v in certificate_data.items() if k != "signature"}
        json_str = json.dumps(cert, indent=2, ensure_ascii=False)
        return json_str.encode("utf-8")


    def verify_rsa_signature_pkcs1(self, public_key_pem: str, message_bytes: bytes, signature_b64: str) -> bool:
        # ... (Mantido o código existente)
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
        # ... (Mantido o código existente)
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