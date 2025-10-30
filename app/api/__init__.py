from flask import Blueprint

# Criar blueprint da API
api_blueprint = Blueprint('api', __name__, url_prefix='/api')

# Importar rotas
from . import auth
