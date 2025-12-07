# BitsOfMe Backend
Este repositório implementa o backend da aplicação denominada BitsOfMe, cosistindo em uma API, a qual é responsável pela autenticação, gestão de carteiras digitais, emissão e verificação de credenciais, comunicação segura entre utilizadores e entidades credenciadoras.

## Autores
M15432 - Ana Silva

A56902 - Eduardo Marciano Meneses

M15856 - Iuri Carrasqueiro

E11762 - Marcos Assunção

E11654 - Rodrigo Santos

## Requisitos
* Python 3.12+
* MongoDB
* pip

## Instalação
Clonar o repositório:

```bash
git clone <URL_DO_REPO>
cd ssi-backend
```

Criar ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instalar dependências:

```bash
pip install -r requirements.txt
```

Configurar o arquivo `.env`:

```env
MONGO_URI=mongodb://localhost:27017/ssi
JWT_SECRET_KEY=change_this
MAIL_DEFAULT_SENDER=example@example.com
MAIL_USERNAME=...
MAIL_PASSWORD=...
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
```

## Execução

```bash
flask run --port=5000
```

API disponível em:

```
http://localhost:5000
```

## Documentação (Swagger / OpenAPI)

A documentação da API é gerada com Swagger (Flasgger).

Com o servidor em execução:

* Interface Swagger UI:
  `http://localhost:5000/apidocs`

Os endpoints e exemplos de request/response podem ser testados diretamente pelo Swagger UI.