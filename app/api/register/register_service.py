from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import DuplicateKeyError
from typing import Dict, Any
from datetime import datetime

class RegService:
    def __init__(self, mongo_client: MongoClient, db_name: str, config):
        self.db = mongo_client[db_name]
        self.config = config
        self.user_data: Collection = self.db["user"]

        self._setup_indexes()

    def _setup_indexes(self):
        self.user_data.create_index("email", unique=True, sparse=True)
        self.user_data.create_index("authenticationKey", unique=True, sparse=True)
        self.user_data.create_index("telefone", unique=True, sparse=True)
        self.user_data.create_index("nif", unique=True, sparse=True)


    def register_ec(self, user_data: Dict[str, str]) -> Dict[str, Any]:
        """
        Registo de uma Nova Entidade Certificadora (EC).
        """
        authentication_key = user_data.get('authenticationKey')
        if self.user_data.find_one({"authenticationKey": authentication_key}):
            return {"success": False, "error": "Chave de autenticação já registada.", "status": 409}

        nif = user_data.get('nif')
        if self.user_data.find_one({"nif": nif}):
            return {"success": False, "error": "NIF já registado.", "status": 409}

        email = user_data.get('email')
        if self.user_data.find_one({"email": email}):
            return {"success": False, "error": "Email já registado.", "status": 409}

        tel = user_data.get('tel')
        if self.user_data.find_one({"telefone": tel}):
            return {"success": False, "error": "Telefone já registado.", "status": 409}

        signkey = user_data.get('certificate')
        name = user_data.get('name')
        tipo = user_data.get('tipo')
        tipo_outro = user_data.get('tipoOutro')

        doc_to_insert = {
            "created_at": datetime.utcnow(),
            "authenticationKey": authentication_key,
            "signkey": signkey,
            "name": name,
            "tipo": tipo,
            "tipoOutro": tipo_outro,
            "nif": nif,
            "email": email,
            "telefone": tel   
        }

        try:
            self.user_data.insert_one(doc_to_insert)
            return {"success": True, "message": "Registo efetuado com sucesso!", "status": 200} 
        except DuplicateKeyError:
            return {"success": False, "error": "Erro: dados já registados (NIF/Email/Telefone/Chave de Autenticação).", "status": 409}
        except Exception as e:
            print(f"Erro ao inserir EC na DB: {e}")
            return {"success": False, "error": "Erro interno ao registar.", "status": 500}