
# ============================================================================
# routes_auth.py - Authentication Routes
# ============================================================================

"""
Route Flask per gestione autenticazione:
- Login (username/password → API Key)
- Logout
- Status check
- Session management
"""

import logging
from flask import request, jsonify, current_app

logger = logging.getLogger(__name__)


def register_auth_routes(app):
    """
    Registra le route di autenticazione nell'app Flask.
    
    Chiamare da fuco.py dopo l'inizializzazione di auth_manager.
    """
    
    @app.route('/api/auth/login', methods=['POST'])
    def auth_login():
        """
        Login utente e ottieni API Key da Cortex.
        
        Request Body:
        {
            "username": "cortex_user",
            "password": "cortex_password"
        }
        
        Response (Success):
        {
            "success": true,
            "username": "cortex_user",
            "message": "Login successful"
        }
        
        Response (Failure):
        {
            "success": false,
            "error": "Invalid username or password"
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'Missing request body'
                }), 400
            
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            # Validazione input
            if not username or not password:
                return jsonify({
                    'success': False,
                    'error': 'Username and password are required'
                }), 400
            
            # Tenta login
            auth_manager = current_app.auth_manager
            result = auth_manager.login(username, password)
            
            if result['success']:
                logger.info(f"Login successful per {username}")
                
                # NON inviare API Key al client!
                return jsonify({
                    'success': True,
                    'username': result['username'],
                    'message': 'Login successful'
                }), 200
            else:
                logger.warning(f"Login fallito per {username}: {result.get('error')}")
                
                return jsonify({
                    'success': False,
                    'error': result.get('error', 'Login failed')
                }), 401
        
        except Exception as e:
            logger.error(f"Errore in auth_login: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/logout', methods=['POST'])
    def auth_logout():
        """
        Logout utente e invalida sessione.
        
        Response:
        {
            "success": true,
            "message": "Logout successful"
        }
        """
        try:
            auth_manager = current_app.auth_manager
            username = auth_manager.get_username() or 'unknown'
            
            auth_manager.logout()
            
            logger.info(f"Logout completato per {username}")
            
            return jsonify({
                'success': True,
                'message': 'Logout successful'
            }), 200
        
        except Exception as e:
            logger.error(f"Errore in auth_logout: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/status', methods=['GET'])
    def auth_status():
        """
        Verifica status autenticazione corrente.
        
        Response:
        {
            "authenticated": true,
            "username": "cortex_user",
            "session_timeout": 1800
        }
        """
        try:
            auth_manager = current_app.auth_manager
            info = auth_manager.get_session_info()
            
            return jsonify(info), 200
        
        except Exception as e:
            logger.error(f"Errore in auth_status: {str(e)}", exc_info=True)
            return jsonify({
                'authenticated': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/refresh', methods=['POST'])
    def auth_refresh():
        """
        Refresh della sessione per estendere timeout.
        Chiamare quando l'utente fa un'azione importante.
        
        Response:
        {
            "success": true,
            "message": "Session refreshed"
        }
        """
        try:
            auth_manager = current_app.auth_manager
            
            if not auth_manager.is_authenticated():
                return jsonify({
                    'success': False,
                    'error': 'Not authenticated'
                }), 401
            
            auth_manager.refresh_session()
            
            return jsonify({
                'success': True,
                'message': 'Session refreshed'
            }), 200
        
        except Exception as e:
            logger.error(f"Errore in auth_refresh: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/validate-key', methods=['POST'])
    def auth_validate_key():
        """
        Valida un API Key facendo test call a Cortex.
        Utile per debug o verifica manuale.
        
        Request Body:
        {
            "api_key": "test_key_123"
        }
        
        Response:
        {
            "valid": true
        }
        """
        try:
            data = request.get_json()
            
            if not data or 'api_key' not in data:
                return jsonify({
                    'valid': False,
                    'error': 'Missing api_key'
                }), 400
            
            auth_manager = current_app.auth_manager
            is_valid = auth_manager.validate_api_key(data['api_key'])
            
            return jsonify({
                'valid': is_valid
            }), 200
        
        except Exception as e:
            logger.error(f"Errore in auth_validate_key: {str(e)}", exc_info=True)
            return jsonify({
                'valid': False,
                'error': 'Internal server error'
            }), 500
    
    
    logger.info("Route di autenticazione registrate con successo")