# ============================================================================
# auth_manager.py - Authentication Manager with Cortex API Key
# ============================================================================

"""
Authentication system for responder actions:
1. Login with username/password (Basic Auth)
2. Retrieves the user's API key from Cortex
3. Stores API key in Redis-backed session (30 min timeout)
4. Subsequent operations use the API key
"""

import logging
import requests
from typing import Optional, Dict
from flask import session
from datetime import timedelta
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


class ResponderAuthManager:
    """
    Manages user authentication for responder operations.
    Uses Cortex API keys stored in Flask/Redis session.
    """
    
    def __init__(self, cortex_host: str, session_timeout: int = 1800):
        """
        Args:
            cortex_host: Cortex server URL
            session_timeout: Session timeout in seconds (default: 30 min)
        """
        self.cortex_host = cortex_host.rstrip('/')
        self.session_timeout = session_timeout
        
        logger.info(f"AuthManager initialized for {cortex_host}")
    
    def login(self, username: str, password: str) -> Dict[str, any]:
        """
        Authenticate the user and retrieve the API key from Cortex.
        
        Workflow:
        1. Validate credentials with Basic Auth on Cortex
        2. Retrieve the user's API key via /api/user/{username}/key
        3. Store the API key in Flask session (stored in Redis)
        
        Args:
            username: Cortex username
            password: Cortex password
        
        Returns:
            Dict with:
            - success: bool
            - username: str (se success)
            - api_key: str (se success)
            - error: str (on failure)
        """
        try:
            # Step 1: Validate credentials and get API key
            api_key_url = f"{self.cortex_host}/api/user/{username}/key"
            
            logger.info(f"Login attempt for user: {username}")
            
            response = requests.get(
                api_key_url,
                auth=HTTPBasicAuth(username, password),
                timeout=10,
                verify=True  # Verify SSL in production
            )
            
            if response.status_code == 200:
                api_key = response.text.strip()
                
                # Step 2: Store in Flask session
                session['cortex_username'] = username
                session['cortex_api_key'] = api_key
                session['cortex_authenticated'] = True
                session.permanent = True  # Usa PERMANENT_SESSION_LIFETIME
                
                logger.info(f"Login successful for {username}, API key retrieved")
                
                return {
                    'success': True,
                    'username': username,
                    'api_key': api_key  # Return only for debug, do not send to client
                }
            
            elif response.status_code == 401:
                logger.warning(f"Login failed for {username}: invalid credentials")
                return {
                    'success': False,
                    'error': 'Invalid username or password'
                }
            
            elif response.status_code == 404:
                logger.warning(f"User {username} not found on Cortex")
                return {
                    'success': False,
                    'error': f'User {username} not found'
                }
            
            else:
                logger.error(f"Cortex API error: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f'Cortex API error: {response.status_code}'
                }
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Cortex connection error: {str(e)}")
            return {
                'success': False,
                'error': f'Connection error: {str(e)}'
            }
        
        except Exception as e:
            logger.error(f"Unexpected error during login: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': 'Internal error'
            }
    
    def logout(self):
        """Log out by clearing the session."""
        username = session.get('cortex_username', 'unknown')
        
        session.pop('cortex_username', None)
        session.pop('cortex_api_key', None)
        session.pop('cortex_authenticated', None)
        
        logger.info(f"Logout completed for {username}")
    
    def is_authenticated(self) -> bool:
        """Check whether the user is authenticated."""
        authenticated = session.get('cortex_authenticated', False)
        
        if authenticated:
            api_key = session.get('cortex_api_key')
            if not api_key:
                logger.warning("Corrupted session: authenticated=True but no API key")
                self.logout()
                return False
            return True
        
        return False
    
    def get_username(self) -> Optional[str]:
        """Get the authenticated username."""
        if self.is_authenticated():
            return session.get('cortex_username')
        return None
    
    def get_api_key(self) -> Optional[str]:
        """Get the authenticated API key."""
        if self.is_authenticated():
            return session.get('cortex_api_key')
        return None
    
    def refresh_session(self):
        """Refresh the session timestamp to extend timeout."""
        if self.is_authenticated():
            session.modified = True
            logger.debug(f"Session refreshed for {self.get_username()}")
    
    def get_session_info(self) -> Dict[str, any]:
        """Return information about the current session."""
        return {
            'authenticated': self.is_authenticated(),
            'username': self.get_username(),
            'session_timeout': self.session_timeout
        }
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate an API key via a test call to Cortex."""
        try:
            test_url = f"{self.cortex_host}/api/responder"
            
            response = requests.get(
                test_url,
                headers={'Authorization': f'Bearer {api_key}'},
                params={'range': '0-1'},
                timeout=5
            )
            
            if response.status_code == 200:
                logger.debug("API key is valid")
                return True
            else:
                logger.warning(f"API key is invalid: HTTP {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"API key validation error: {str(e)}")
            return False


def init_auth_manager(app, cortex_host: str, session_timeout: int = 1800):
    """
    Initialize AuthManager and attach it to the Flask app.
    
    Args:
        app: Flask app instance
        cortex_host: Cortex URL
        session_timeout: Session timeout (seconds)
    """
    auth_manager = ResponderAuthManager(cortex_host, session_timeout)
    app.auth_manager = auth_manager
    
    logger.info("AuthManager initialized and attached to the app")
    return auth_manager