from flask import request, jsonify, Blueprint
from flasgger import swag_from
import os

def create_register_controller(reg_service):
    """
    Factory que cria e retorna o controller de registo.
    """
    bp = Blueprint('register', __name__)
    docs = os.path.join(os.path.dirname(__file__), 'docs')
    
    @bp.post('/register/ec-register') 
    @swag_from(os.path.join(docs, 'register_ec.yml'))
    def register_ec():
        """Regista uma nova Entidade Credenciadora."""
        data = request.get_json(silent=True)
        
        if not data:
            return jsonify({'error': 'Os dados devem ser JSON.'}), 400

        result = reg_service.register_ec(data)

        if not result['success']:
            return jsonify({'error': result['error']}), result['status']
        
        return jsonify({'message': result['message']}), result['status']

    return bp