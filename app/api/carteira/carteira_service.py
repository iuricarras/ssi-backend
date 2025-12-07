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

        # 1. Decifrar a string JSON (retorna str)
        decrypted_json_str = self._decrypt_data_to_json_str(data_stored, master_key, salt)
        
        # 2. Desserializar para um dicionário Python
        try:
            decrypted_data = json.loads(decrypted_json_str)
        except json.JSONDecodeError:
            # Isto pode ocorrer se a chave mestra for inválida e a decifra retornar lixo.
            raise ValueError("Falha na decifra ou chave mestra incorreta.")
        
        # 3. Retornar os dados decifrados e desserializados
        return decrypted_data
     
    
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
                self._decrypt_data_to_json_str(data_stored, master_key, salt)
            except Exception:
                raise ValueError("Chave mestra incorreta.")

        # Primeiro, formatamos a estrutura de dados (cifrando os valores)
        structured_data = self._format_and_encrypt_data(data, master_key)
        
        # Apenas guardamos os tipos (metadados) para a visualização pública
        data_type = self._get_data_types(data)
        
        # O structured_data que está a ser passado aqui é a estrutura cifrada final
        # Precisamos de um novo salt para a cifra
        salt = secrets.token_hex(16)
        
        # Certificamos que o dado cifrado é serializado para uma string JSON antes de cifrar
        data_to_save, salt = self._encrypt_data(structured_data, master_key, salt)
        
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
            # Obtém os dados decifrados como um dicionário
            decrypted_carteira_data = self.get_carteira_data(user_id, master_key) 
        except ValueError:
            raise ValueError("Chave mestra incorreta.")
        except Exception as e:
            raise Exception(f"Erro ao obter carteira: {e}")

        
        existing_data: List[Dict[str, Any]] = []
        
        # Adicionar dados pessoais existentes
        # ATENÇÃO: decrypted_carteira_data é um dicionário Python (já decifrado e desserializado)
        # O método update_carteira_data espera o formato de lista aninhada (ex: [{tipo: 'personalData', chave: '...', valor: '...'}])
        
        # 1. Transformar o dicionário decifrado de volta para o formato de lista esperado por update_carteira_data
        
        # Dados Pessoais: de [ {name: 'chave', value: 'valor'} ] para [{tipo: 'personalData', chave: 'chave', valor: 'valor'}]
        for item in decrypted_carteira_data.get('personalData', []):
            # O valor já está decifrado aqui!
            existing_data.append({
                'tipo': 'personalData',
                'chave': item.get('name'),
                'valor': item.get('value')
            })
            
        # Certificados: de [ {nome: 'Cert', campo1: 'valor1', ...} ] para [{tipo: 'certificate', nome: 'Cert', campos: [{chave: 'campo1', valor: 'valor1'}, ...]}]
        for cert in decrypted_carteira_data.get('certificates', []):
            cert_nome = cert.get('nome')
            campos_cert = []
            
            # Percorrer campos do certificado (que já estão decifrados)
            for key, value in cert.items():
                if key != 'nome' and value is not None:
                    campos_cert.append({
                        'chave': key,
                        'valor': value
                    })
            
            if cert_nome:
                 existing_data.append({
                    'tipo': 'certificate',
                    'nome': cert_nome,
                    'campos': campos_cert
                })
        
        # 2. Adicionar o novo certificado
        cert_nome = certificate_data.get('nome')
        
        if not cert_nome:
            raise ValueError("Dados de certificado inválidos (nome ausente).")

        new_cert_campos = []
        
        for key, value in certificate_data.items():
            if key not in ['nome', 'signature'] and value is not None:
                new_cert_campos.append({'chave': key, 'valor': value})

        existing_data.append({
            'tipo': 'certificate',
            'nome': cert_nome,
            'campos': new_cert_campos
        })


        # 3. Chamar update_carteira_data com a lista completa (para que ele cifre TUDO de novo)
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
        Retorna os tipos de dados presentes na carteira (usado para visualização pública).
        A entrada 'data' é a lista de dicionários no formato de lista aninhada:
        [{tipo: 'personalData', chave: '...', valor: '...'}, ...]
        """
        types = {'personalData': [], 'certificates': []}

        for item in data:
            if item.get('tipo') == 'personalData':
                # 'chave' contém o nome do campo
                types['personalData'].append(item.get('chave')) 
            elif item.get('tipo') == 'certificate':
                # 'nome' contém o nome do certificado
                types['certificates'].append(item.get('nome'))

        return types
        
    # Esta função está obsoleta. Agora, get_carteira_data decifra e desserializa.
    # Esta função também deve ser alterada, pois o dado na DB é uma string JSON cifrada (data_to_save).
    # Deixei o método _format_and_encrypt_data para tratar os dados DESSERIALIZADOS
    # e _decrypt_data_to_json_str para obter a string JSON decifrada.
    def _get_encrypted_data(self, data: dict, master_key: str, salt: str) -> dict:
        """
        DEPRECATED: Função original que esperava dados já decifrados e formatados como dicionário.
        
        Agora, a decifra total é feita em `get_carteira_data`. Esta função foi renomeada no backend para:
        _decrypt_data_to_json_str (que retorna string JSON decifrada)
        _format_and_encrypt_data (que faz a cifragem final dos valores)
        
        Para evitar confusão, vou renomear para a função que realmente faz a decifra da string cifrada para JSON string.
        """
        raise NotImplementedError("Use _decrypt_data_to_json_str() em vez de _get_encrypted_data()")

    def _format_and_encrypt_data(self, data: list, master_key: str) -> dict:
        """
        Processa a lista de dados recebida (lista aninhada), cifrando cada valor individualmente.
        Retorna o dicionário cifrado (que será serializado para JSON e depois cifrado no update_carteira_data).
        """
        # Primeiro, precisamos obter o salt da carteira atual (ou gerar um novo temporário para o hash)
        # Como o update_carteira_data está a ser refatorado para gerir a cifra completa, esta função
        # apenas faz a cifragem dos valores individuais.

        # No update_carteira_data, o salt é gerado ANTES de chamar esta função, mas 
        # para a hash individual, a hash é gerada internamente. 
        # Vamos assumir que esta função é chamada DENTRO de update_carteira_data e que
        # ele irá gerar o salt final.

        # Como a função update_carteira_data original gerava o salt APÓS chamar esta função
        # vamos precisar de um salt temporário para a cifragem individual aqui, que será descartado
        # ou passá-lo como argumento.

        # REFATORANDO: vamos passar a master_key e o salt para a função de cifragem individual.
        # No entanto, a cifragem é feita no _encrypt_value e _decrypt_value, que espera o master_key e salt.
        
        # NOTE: A função update_carteira_data NÃO estava a passar o salt para _encrypt_data (o nome antigo). 
        # O _encrypt_data antigo estava a gerar a hash internamente. Vamos corrigir isso no update_carteira_data.
        
        # Vamos reformular esta função para apenas construir o Dicionário de Dados Pessoais / Certificados Cifrados.
        
        # NOTA: O update_carteira_data (refatorado) chama esta função, e DEPOIS chama _encrypt_data (o método de cifra AES final).
        # Vamos manter o nome e a estrutura original (data_str, master_key, salt).
        
        new_personal_data = []
        new_certificates_map = {} 

        # Para que o _encrypt_value funcione, precisamos do salt que será usado no final.
        # Como ele é gerado no update_carteira_data, vamos usar um salt temporário aqui 
        # e confiar que o update_carteira_data irá gerar o salt final e passá-lo para a cifra AES.
        # Isto é um PONTO DE BUG no código original.

        # Vamos assumir que `update_carteira_data` vai gerar o `salt` e passá-lo para cá.
        # MUDANÇA: `_format_and_encrypt_data` agora recebe `salt` como argumento.
        # Por agora, mantemos o `update_carteira_data` refatorado no passo 2 a gerir o salt.
        # Vamos corrigir o _encrypt_data original (que agora será _encrypt_data_to_json_str) e 
        # *remover* o método _get_encrypted_data de forma limpa.
        
        # Esta função (antiga _encrypt_data) foi removida/substituída. 
        # A lógica de cifrar valor por valor deve ser feita DENTRO do update_carteira_data
        
        # Vamos usar o _encrypt_data e _decrypt_data que já existem na classe (no final do ficheiro)
        
        # MANTENDO O CÓDIGO ORIGINAL, a única função que precisa ser corrigida é `_decrypt_value` 
        # e a forma como `get_carteira_data` a chama.
        
        # Vamos reverter o que foi feito na função `_get_encrypted_data` (agora chamada) e garantir
        # que a função que a chama (get_carteira_data) faz o json.loads.
        
        # CORREÇÃO AO REVERTER A ESTRUTURA ORIGINAL DE _get_encrypted_data:
        
        # O nome do método é confuso. `_get_encrypted_data` **não** retorna dados cifrados.
        # Ele recebe dados cifrados (string JSON de hex) e *retorna* dados decifrados (dicionário).

        # Vou renomeá-la para refletir a sua nova responsabilidade de decifrar para Dicionário:
        # A função que decifra o valor individual é `_decrypt_value`

        pass # Vamos ignorar este método por agora e corrigir as funções principais


    def _decrypt_data_to_json_str(self, data_encrypted_dict: dict, master_key: str, salt: str) -> str:
        """
        Decifra todos os valores cifrados no dicionário (data_encrypted_dict) e retorna a estrutura
        decifrada como uma **string JSON**.
        """
        
        # A nova estrutura de `data_encrypted_dict` é:
        # { "personalData": [ {name: 'chave', value: 'hex_cifrado'}, ... ], 
        #   "certificates": [ {nome: 'cert', campo: 'hex_cifrado', ...}, ... ] }
        
        
        decrypted_personal_data = [{
                    'name': item.get('name'),
                    'value': self._decrypt_value(item.get('value'), master_key, salt)
                } for item in data_encrypted_dict.get('personalData', [])
            ]
        
        decrypted_certificates = [{
                    k: (self._decrypt_value(v, master_key, salt) if k != 'nome' else v)
                    for k, v in cert.items()
                }for cert in data_encrypted_dict.get('certificates', [])
            ]
            
        # Reconstruir o dicionário original com valores decifrados
        decrypted_data_dict = {
            "personalData": decrypted_personal_data,
            "certificates": decrypted_certificates
        }
        
        # Retorna como string JSON
        return json.dumps(decrypted_data_dict, ensure_ascii=False)


    # O update_carteira_data também precisa de ser corrigido para usar o novo _decrypt_data_to_json_str
    
    
    # ----------------------------------------------------
    # O CÓDIGO ORIGINAL ERA:
    # def _get_encrypted_data(self, data: dict, master_key: str, salt: str) -> dict:
    #     """
    #     Percorre a estrutura de dados armazenada e decifra cada valor individualmente.
    #     """
    #     return {"personalData": [{
    #                 'name': item.get('name'),
    #                 'value': self._decrypt_value(item.get('value'), master_key, salt)
    #             } for item in data.get('personalData', [])
    #         ],"certificates": [{
    #                 k: (self._decrypt_value(v, master_key, salt) if k != 'nome' else v)
    #                 for k, v in cert.items()
    #             }for cert in data.get('certificates', [])
    #         ]
    #     }
    # Onde data era `data_stored` (string JSON da DB). A chamada era:
    # return self._get_encrypted_data(data_stored, master_key, salt)
    # ----------------------------------------------------
    
    # VOU CORRIGIR get_carteira_data E update_carteira_data para funcionar com o código original (apenas adicionando json.loads/json.dumps)

    def get_carteira_data(self, user_id: str, master_key: str) -> dict:
        """
        Recupera os dados da carteira do banco de dados e decifra-os usando a chave mestra.
        """
        carteira_doc = self.carteiras_collection.find_one({'user_id': user_id})
   
        if not carteira_doc:
            return self._get_initial_data()

        salt = carteira_doc.get('salt')
        data_stored_hex = carteira_doc.get('data') # Data é uma string Hex

        # 1. Decifrar a string Hex para uma string JSON decifrada
        decrypted_json_str = self._decrypt_value_hex_to_str(data_stored_hex, master_key, salt)
        
        # 2. Converter a string JSON decifrada para um dicionário Python
        try:
            data_dict = json.loads(decrypted_json_str)
        except json.JSONDecodeError:
            raise ValueError("Falha na decifra ou chave mestra incorreta.")
        
        # A estrutura retornada é o dicionário de dados decifrados
        return data_dict
    
    
    def update_carteira_data(self, user_id: str, data: dict, master_key: str) -> bool:
        """
        Cifra os valores dos dados fornecidos e atualiza a carteira no banco de dados.
        """
        # Verificar se a chave mestra é válida para os dados existentes
        carteira_doc = self.carteiras_collection.find_one({'user_id': user_id})
        if carteira_doc:
            salt = carteira_doc.get('salt')
            data_stored_hex = carteira_doc.get('data')
            try:
                # Tenta decifrar. Se falhar, levanta ValueError.
                self._decrypt_value_hex_to_str(data_stored_hex, master_key, salt)
            except Exception:
                raise ValueError("Chave mestra incorreta.")

        # 1. Preparar a estrutura de dados cifrada para ser salva
        
        # Novo salt para cifrar o JSON completo
        salt = secrets.token_hex(16)
        
        # 2. Primeiro, formatamos a estrutura de dados (cifrando os valores individuais)
        # data é a lista no formato do front: [{tipo: 'personalData', chave: '...', valor: '...'}, ...]
        
        # Convertemos a lista de volta para o formato de dicionário cifrado (que será serializado para JSON)
        data_to_serialize = self._format_data_for_encryption(data, master_key, salt)
        
        # 3. Serializar o dicionário cifrado em string JSON
        json_str_to_encrypt = json.dumps(data_to_serialize, ensure_ascii=False)
        
        # 4. Cifrar a string JSON completa (retorna Hex String)
        data_to_save_hex = self._encrypt_value_str_to_hex(json_str_to_encrypt, master_key, salt)
        
        # 5. Guardar os tipos (metadados) para a visualização pública
        data_type = self._get_data_types(data)
        
        
        # dar update ou inserir o documento
        try:
            self.carteiras_collection.update_one(
                {'user_id': user_id},
                {'$set': {'type': data_type, 'data': data_to_save_hex, 'salt': salt}},
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
            # Obtém os dados decifrados como um dicionário
            decrypted_carteira_data = self.get_carteira_data(user_id, master_key) 
        except ValueError:
            raise ValueError("Chave mestra incorreta.")
        except Exception as e:
            raise Exception(f"Erro ao obter carteira: {e}")

        
        existing_data: List[Dict[str, Any]] = []
        
        # 1. Transformar o dicionário decifrado de volta para o formato de lista esperado por update_carteira_data
        
        # Dados Pessoais: de [ {name: 'chave', value: 'valor'} ] para [{tipo: 'personalData', chave: 'chave', valor: 'valor'}]
        for item in decrypted_carteira_data.get('personalData', []):
            # O valor já está decifrado aqui!
            existing_data.append({
                'tipo': 'personalData',
                'chave': item.get('name'),
                'valor': item.get('value')
            })
            
        # Certificados: de [ {nome: 'Cert', campo1: 'valor1', ...} ] para [{tipo: 'certificate', nome: 'Cert', campos: [{chave: 'campo1', valor: 'valor1'}, ...]}]
        for cert in decrypted_carteira_data.get('certificates', []):
            cert_nome = cert.get('nome')
            campos_cert = []
            
            # Percorrer campos do certificado (que já estão decifrados)
            for key, value in cert.items():
                if key != 'nome' and key != 'signature' and value is not None:
                    campos_cert.append({
                        'chave': key,
                        'valor': value
                    })
            
            if cert_nome:
                 existing_data.append({
                    'tipo': 'certificate',
                    'nome': cert_nome,
                    'campos': campos_cert
                })
        
        # 2. Adicionar o novo certificado
        cert_nome = certificate_data.get('nome')
        
        if not cert_nome:
            raise ValueError("Dados de certificado inválidos (nome ausente).")

        new_cert_campos = []
        
        for key, value in certificate_data.items():
            if key not in ['nome', 'signature'] and value is not None:
                new_cert_campos.append({'chave': key, 'valor': value})

        existing_data.append({
            'tipo': 'certificate',
            'nome': cert_nome,
            'campos': new_cert_campos
        })


        # 3. Chamar update_carteira_data com a lista completa (para que ele cifre TUDO de novo)
        # O método update_carteira_data tratará da cifragem e salvamento.
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
        Retorna os tipos de dados presentes na carteira (usado para visualização pública).
        A entrada 'data' é a lista de dicionários no formato de lista aninhada:
        [{tipo: 'personalData', chave: '...', valor: '...'}, ...]
        """
        types = {'personalData': [], 'certificates': []}

        for item in data:
            if item.get('tipo') == 'personalData':
                # 'chave' contém o nome do campo
                types['personalData'].append(item.get('chave')) 
            elif item.get('tipo') == 'certificate':
                # 'nome' contém o nome do certificado
                types['certificates'].append(item.get('nome'))

        return types
        
    def _format_data_for_encryption(self, data: list, master_key: str, salt: str) -> dict:
        """
        Processa a lista de dados recebida (lista aninhada do front) e cifra cada valor individualmente.
        Retorna o Dicionário no formato:
        { "personalData": [ {name: 'chave', value: 'hex_cifrado'}, ... ], 
          "certificates": [ {nome: 'cert', campo: 'hex_cifrado', ...}, ... ] }
        """
        new_personal_data = []
        new_certificates_map = {} 

        for item in data:
            if item.get('tipo') == 'personalData':
                new_personal_data.append({
                    'name': item.get('chave', ''),
                    'value': self._encrypt_value_str_to_hex(item.get('valor', ''), master_key, salt)
                })
            elif item.get('tipo') == 'certificate':
                cert_nome = item.get('nome')
                if cert_nome not in new_certificates_map:
                    new_certificates_map[cert_nome] = {'nome': cert_nome}
                
                # Certificados vêm como lista de campos (do frontend/add_certificate)
                for campo in item.get('campos', []):
                    new_certificates_map[cert_nome][campo['chave']] = self._encrypt_value_str_to_hex(campo['valor'], master_key, salt)
                
        return {
            "personalData": new_personal_data,
            "certificates": list(new_certificates_map.values())
        }

    def _decrypt_value_hex_to_str(self, data_encrypted_hex: str, master_key: str, salt: str) -> str:
        """
        Decifra a string Hex (que representa uma string JSON) para uma string JSON decifrada.
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

            data_bytes = bytes.fromhex(data_encrypted_hex)
            data_decrypted = decryptor.update(data_bytes) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(data_decrypted) + unpadder.finalize()
            
            data_str = data.decode('utf-8')
            return data_str
        except Exception:
            # Captura erro de bytes, de decifra, etc. e levanta ValueError para
            # ser capturado no controller/serviço superior
            raise ValueError("Falha na decifra")

    def _encrypt_value_str_to_hex(self, value: str, master_key: str, salt: str) -> str:
        """ 
        Cifra uma string (pode ser o valor individual ou a string JSON completa) 
        usando AES-CBC e retorna em formato hexadecimal.
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
        # O valor é a string que será cifrada (pode ser um valor simples ou o JSON completo)
        padded_data = padder.update(value.encode('utf-8')) + padder.finalize()
        
        data_reencrypted = encryptor.update(padded_data) + encryptor.finalize()
        return data_reencrypted.hex()