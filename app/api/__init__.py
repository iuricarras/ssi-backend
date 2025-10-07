from flask import Blueprint

# Todos os endpoint utilizados começam com /api
api_blueprint = Blueprint('api', __name__, url_prefix='/api')

from . import auth, main