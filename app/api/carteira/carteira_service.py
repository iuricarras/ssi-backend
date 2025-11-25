import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CarteiraService:
    """
    Serviço responsável pela lógica de negócio da carteira digital:
    validação da chave mestra, encriptação/desencriptação e persistência.
    """

    def __init__(self, mongo_client, db_name, config):
        self.db = mongo_client[db_name]
        self.config = config
        
        # A coleção onde os dados da carteira serão armazenados
        self.carteiras_collection = self.db['carteiras'] 

    def verify_master_key(self, user_id: str, key_input: str) -> bool:
        """
        Verifica se a chave mestra fornecida é válida.
        (Lógica mockada).
        """
        CHAVE_MESTRA_SECRETA = "a_sua_chave_real_e_segura" 
        
        if key_input == CHAVE_MESTRA_SECRETA:
            return True
        return False

    def get_carteira_data(self, user_id: str, master_key: str) -> dict:
        """
        Busca os dados do DB e retorna-os, desencriptados ou com o mock inicial.
        """
        carteira_doc = self.carteiras_collection.find_one({'user_id': user_id})
   
        if not carteira_doc:
            return self._get_initial_data()

        ## Decifrar os dados
        data_str = self._get_encrypted_data(
            data_encrypted=carteira_doc.get('data'),
            master_key=master_key,
            salt=carteira_doc.get('salt'))

        # Gerar novo nounce para cifrar novamente
        data_reencrypted, nounce = self._encrypt_data(data_str, master_key)
        # Atualizar dados cifrados e nounce no MongoDB
        self.carteiras_collection.update_one(
            {'user_id': user_id},
            {'$set': {
                'data': data_reencrypted,
                'salt': nounce,
            }},
            upsert=True
        )
        
        return data_str
     
    
    def update_carteira_data(self, user_id: str, data: dict) -> bool:
        """
        Recebe a lista de dados, ENCRIPTA-a e SALVA no MongoDB.
        """
        data_to_save = self._reconstruct_data_structure(data)
        
        try:
            data_encrypted, nounce = self._encrypt_data(data_to_save, master_key)
            # Usar upsert=True: insere se não existir, atualiza se existir
            self.carteiras_collection.update_one(
                {'user_id': user_id},
                {'$set': {'data': data_encrypted, 'salt': nounce}},
                upsert=True
            )
            return True
        except Exception as e:
            print(f"ERRO ao salvar no MongoDB para o user {user_id}: {e}")
            return False

    # --- Funções Auxiliares ---

    def _get_initial_data(self) -> dict:
        """ Retorna a estrutura inicial (mock) para uma carteira nova. """
        return {
            "personalData": [
                {"name": "Data de Nascimento", "value": "11/12/2004"},
                {"name": "Telemóvel", "value": "+351 927 087 206"}
            ],
            "certificates": [
                {
                    "nome": "Habilitação Académica",
                    "curso": "Licenciatura em Eng. Informática",
                    "entidade": "UBI",
                    "emissão": "15/07/2025",
                    "nota": "17 valores"
                }
            ]
        }
        
    def _reconstruct_data_structure(self, data: list) -> dict:
        """ Converte a lista plana do frontend para a estrutura de dicionário. """
        new_personal_data = []
        new_certificates_map = {} 

        for item in data:
            if item.get('tipo') == 'personalData':
                new_personal_data.append({
                    'name': item.get('chave', ''),
                    'value': item.get('valor', '')
                })
            elif item.get('tipo') == 'certificate':
                cert_nome = item.get('nome')
                if cert_nome not in new_certificates_map:
                    new_certificates_map[cert_nome] = {'nome': cert_nome}
                
                for campo in item.get('campos', []):
                    new_certificates_map[cert_nome][campo['chave']] = campo['valor']

        return {
            "personalData": new_personal_data,
            "certificates": list(new_certificates_map.values())
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

        data_decrypted = decryptor.update(data_encrypted) + decryptor.finalize()
        data_str = data_decrypted.decode('utf-8')
        return data_str

    def _encrypt_data(self, data_str: str, master_key: str) -> tuple:
        """ Cifra os dados da carteira com a chave mestra. """
        nounce = Random.get_random_bytes(16)
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