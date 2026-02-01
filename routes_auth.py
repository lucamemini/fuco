
# ============================================================================
# routes_auth.py - Authentication Routes
# ============================================================================

"""
Flask routes for authentication management:
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
    Register authentication routes in the Flask app.
    
    Call from fuco.py after initializing auth_manager.
    """
    if app.config.get('AUTH_ROUTES_REGISTERED'):
        logger.info("Authentication routes already registered, skipping")
        return
    app.config['AUTH_ROUTES_REGISTERED'] = True
    
    @app.route('/api/auth/login', methods=['POST'])
    def auth_login():
        """
        Log in a user and obtain an API Key from Cortex.
        
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
            
            # Input validation
            if not username or not password:
                return jsonify({
                    'success': False,
                    'error': 'Username and password are required'
                }), 400
            
            # Attempt login
            auth_manager = current_app.auth_manager
            result = auth_manager.login(username, password)
            
            if result['success']:
                logger.info(f"Login successful for {username}")
                
                # Do NOT send API Key to the client!
                return jsonify({
                    'success': True,
                    'username': result['username'],
                    'message': 'Login successful'
                }), 200
            else:
                logger.warning(f"Login failed for {username}: {result.get('error')}")
                
                return jsonify({
                    'success': False,
                    'error': result.get('error', 'Login failed')
                }), 401
        
        except Exception as e:
            logger.error(f"Error in auth_login: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/logout', methods=['POST'])
    def auth_logout():
        """
        Log out the user and invalidate the session.
        
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
            
            logger.info(f"Logout completed for {username}")
            
            return jsonify({
                'success': True,
                'message': 'Logout successful'
            }), 200
        
        except Exception as e:
            logger.error(f"Error in auth_logout: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/status', methods=['GET'])
    def auth_status():
        """
        Check current authentication status.
        
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
            logger.error(f"Error in auth_status: {str(e)}", exc_info=True)
            return jsonify({
                'authenticated': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/refresh', methods=['POST'])
    def auth_refresh():
        """
        Refresh the session to extend timeout.
        Call when the user performs an important action.
        
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
            logger.error(f"Error in auth_refresh: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': 'Internal server error'
            }), 500
    
    
    @app.route('/api/auth/validate-key', methods=['POST'])
    def auth_validate_key():
        """
        Validate an API Key by performing a test call to Cortex.
        Useful for debugging or manual verification.
        
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
            logger.error(f"Error in auth_validate_key: {str(e)}", exc_info=True)
            return jsonify({
                'valid': False,
                'error': 'Internal server error'
            }), 500
    
    
    logger.info("Authentication routes registered successfully")