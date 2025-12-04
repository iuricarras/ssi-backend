import hashlib
import json
import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from typing import Dict, Any, List

class CarteiraService:
    """
    Serviço responsável pela lógica de negócio da carteira digital:
    validação da chave mestra, encriptação/desencriptação e persistência.
    """

    def __init__(self, mongo_client, db_name, config):
        self.db = mongo_client[db_name]
        self.config = config
        
        # A coleção onde os dados da carteira serão armazenhados
        self.carteiras_collection = self.db['carteiras'] 
        self.users_collection = self.db['user']

    def get_carteira_data(self, user_id: str, master_key: str) -> dict:
        """
        Recupera os dados da carteira do banco de dados e decifra-os usando a chave mestra.
        """
        carteira_doc = self.carteiras_collection.find_one({'user_id': user_id})
   
        if not carteira_doc:
            return self._get_initial_data()

        salt = carteira_doc.get('salt')
        data_stored = carteira_doc.get('data')

        return self._get_encrypted_data(data_stored, master_key, salt)
     
    
    def update_carteira_data(self, user_id: str, data: dict, master_key: str) -> bool:
        """
        Cifra os valores dos dados fornecidos e atualiza a carteira no banco de dados.
        """
        # Verificar se a chave mestra é válida para os dados existentes
        # É valida se conseguir decifrar os dados atuais com a chave fornecida 
        carteira_doc = self.carteiras_collection.find_one({'user_id': user_id})
        if carteira_doc:
            salt = carteira_doc.get('salt')
            data_stored = carteira_doc.get('data')
            try:
                # Tenta decifrar. Se falhar, levanta ValueError.
                self._get_encrypted_data(data_stored, master_key, salt)
            except Exception:
                raise ValueError("Chave mestra incorreta.")

        salt = secrets.token_hex(16)
        data_to_save = self._encrypt_data(data, master_key, salt)
        data_type = self._get_data_types(data)
        
        # dar update ou inserir o documento
        try:
            self.carteiras_collection.update_one(
                {'user_id': user_id},
                {'$set': {'type': data_type, 'data': data_to_save, 'salt': salt}},
                upsert=True
            )
            return True
        except Exception as e:
            # Capturar exceções de DB, etc.
            print(f"Erro ao salvar carteira: {e}")
            return False

    def add_certificate(self, user_id: str, certificate_data: Dict[str, Any], master_key: str) -> bool:
        """
        Adiciona um novo certificado à carteira do utilizador após a aprovação da notificação.
        Requer a master_key do utilizador.
        """
        
        try:
            decrypted_carteira_data = self.get_carteira_data(user_id, master_key)
        except ValueError:
            raise ValueError("Chave mestra incorreta.")
        except Exception as e:
            raise Exception(f"Erro ao obter carteira: {e}")

        
        existing_data: List[Dict[str, Any]] = []
        
        # Adicionar dados pessoais existentes
        for item in decrypted_carteira_data.get('personalData', []):
            existing_data.append({
                'tipo': 'personalData',
                'chave': item.get('name'),
                'valor': item.get('value')
            })
            
        # Adicionar certificados existentes (reformata os campos de volta para a estrutura de lista aninhada esperada)
        for cert in decrypted_carteira_data.get('certificates', []):
            cert_nome = cert.get('nome')
            campos_cert = []
            
            for key, value in cert.items():
                if key != 'nome' and value is not None:
                    campos_cert.append({
                        'chave': key,
                        'valor': value
                    })
            
            existing_data.append({
                'tipo': 'certificate',
                'nome': cert_nome,
                'campos': campos_cert
            })
        
        cert_nome = certificate_data.get('nome')
        
        if not cert_nome:
            raise ValueError("Dados de certificado inválidos (nome ausente).")

        new_cert_campos = []
        
        for key, value in certificate_data.items():
            if key not in ['nome', 'signature', 'entidade', 'emissao'] and value is not None:
                new_cert_campos.append({'chave': key, 'valor': value})

        if 'entidade' in certificate_data: new_cert_campos.append({'chave': 'Entidade', 'valor': certificate_data['entidade']})
        if 'emissao' in certificate_data: new_cert_campos.append({'chave': 'Emissão', 'valor': certificate_data['emissao']})

        existing_data.append({
            'tipo': 'certificate',
            'nome': cert_nome,
            'campos': new_cert_campos
        })


        return self.update_carteira_data(user_id, existing_data, master_key)


    def get_user_by_username(self, username: str) -> dict:
        """ 
        Busca as informações básicas de um utilizador pelo seu nome de utilizador. 
        """
        user = self.users_collection.find_one({"username": username}, {"_id": 1, "nome": 1, "username": 1, "email": 1})
        if user:
            user['id'] = str(user['_id'])
            del user['_id']
        return user

    def get_carteira_public_data(self, user_id: str) -> dict:
        """
        Retorna a estrutura pública da carteira (nomes dos campos) sem os valores sensíveis.
        """
        carteira_doc = self.carteiras_collection.find_one({'user_id': user_id})
        
        if not carteira_doc:
            return self._get_initial_data()

        personal_data = []
        certificates = []
        
        data_types = carteira_doc.get('type', {})
        
        if 'personalData' in data_types:
            for key in data_types['personalData']:
                personal_data.append({'name': key})
        
        if 'certificates' in data_types:
            for cert_name in data_types['certificates']:
                certificates.append({'nome': cert_name})

        return {
            "personalData": personal_data,
            "certificates": certificates
        }


    # --- Funções Auxiliares ---

    def _get_initial_data(self) -> dict:
        """ 
        Retorna uma estrutura vazia padrão para uma nova carteira. 
        """
        return {
            "personalData": [],
            "certificates": []
        }

    def _get_data_types(self, data: list) -> dict:
        """ 
        Retorna os tipos de dados presentes na carteira. 
        """
        types = {'personalData': [], 'certificates': []}

        for item in data:
            if item.get('tipo') == 'personalData':
                types['personalData'].append(item.get('chave'))
            elif item.get('tipo') == 'certificate':
                types['certificates'].append(item.get('nome'))

        return types
        
    def _get_encrypted_data(self, data: dict, master_key: str, salt: str) -> dict:
        """
        Percorre a estrutura de dados armazenada e decifra cada valor individualmente.
        """
        return {"personalData": [{
                    'name': item.get('name'),
                    'value': self._decrypt_value(item.get('value'), master_key, salt)
                } for item in data.get('personalData', [])
            ],"certificates": [{
                    k: (self._decrypt_value(v, master_key, salt) if k != 'nome' else v)
                    for k, v in cert.items()
                }for cert in data.get('certificates', [])
            ]
        }

    def _encrypt_data(self, data: list, master_key: str, salt: str) -> dict:
        """
        Processa a lista de dados recebida, cifrando cada valor individualmente.
        """
        new_personal_data = []
        new_certificates_map = {} 

        for item in data:
            if item.get('tipo') == 'personalData':
                new_personal_data.append({
                    'name': item.get('chave', ''),
                    'value': self._encrypt_value(item.get('valor', ''), master_key, salt)
                })
            elif item.get('tipo') == 'certificate':
                cert_nome = item.get('nome')
                if cert_nome not in new_certificates_map:
                    new_certificates_map[cert_nome] = {'nome': cert_nome}
                
                # Certificados vêm como lista de campos (do frontend/add_certificate)
                for campo in item.get('campos', []):
                    new_certificates_map[cert_nome][campo['chave']] = self._encrypt_value(campo['valor'], master_key, salt)
                
                # Se o certificado já estiver no novo formato de mapa (após ser decifrado e re-entrar no loop)
                if 'campos' not in item:
                     for key, value in item.items():
                        if key not in ['nome', 'tipo'] and value is not None:
                            new_certificates_map[cert_nome][key] = self._encrypt_value(value, master_key, salt)


        return {
            "personalData": new_personal_data,
            "certificates": list(new_certificates_map.values())
        }


    def _decrypt_value(self, data_encrypted: str, master_key: str, salt: str) -> str:
        """ 
        Decifra um valor individual. 
        """
        try:
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
        except Exception:
            raise ValueError("Falha na decifra")

    def _encrypt_value(self, value: str, master_key: str, salt: str) -> str:
        """ 
        Cifra um valor individual usando AES-CBC e retorna em formato hexadecimal. 
        """
        h = hashlib.new('sha256')
        h.update(f"{master_key}.{salt}".encode('utf-8'))

        enc_secret = h.digest()

        enc_key = enc_secret[:16]
        enc_iv = enc_secret[16:]

        enc_algorithm = algorithms.AES(enc_key)
        enc_mode = modes.CBC(enc_iv)

        enc_cipher = Cipher(enc_algorithm, enc_mode)
        encryptor = enc_cipher.encryptor()  
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(value.encode('utf-8')) + padder.finalize()
        
        data_reencrypted = encryptor.update(padded_data) + encryptor.finalize()
        return data_reencrypted.hex()