# ============================================================================
# auth_manager.py - Authentication Manager con API Key Cortex
# ============================================================================

"""
Sistema di autenticazione per responder actions:
1. Login con username/password (Basic Auth)
2. Ottiene API Key utente da Cortex
3. Salva API Key in sessione Redis (timeout 30min)
4. Operazioni successive usano API Key
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
    Gestisce autenticazione utenti per responder operations.
    Usa API Key di Cortex salvate in sessione Flask/Redis.
    """
    
    def __init__(self, cortex_host: str, session_timeout: int = 1800):
        """
        Args:
            cortex_host: URL del server Cortex
            session_timeout: Timeout sessione in secondi (default: 30min)
        """
        self.cortex_host = cortex_host.rstrip('/')
        self.session_timeout = session_timeout
        
        logger.info(f"AuthManager inizializzato per {cortex_host}")
    
    def login(self, username: str, password: str) -> Dict[str, any]:
        """
        Autentica utente e ottiene API Key da Cortex.
        
        Workflow:
        1. Valida credenziali con Basic Auth su Cortex
        2. Ottiene API Key dell'utente via /api/user/{username}/key
        3. Salva API Key in sessione Flask (stored in Redis)
        
        Args:
            username: Username Cortex
            password: Password Cortex
        
        Returns:
            Dict con:
            - success: bool
            - username: str (se success)
            - api_key: str (se success)
            - error: str (se fallimento)
        """
        try:
            # Step 1: Valida credenziali e ottieni API Key
            api_key_url = f"{self.cortex_host}/api/user/{username}/key"
            
            logger.info(f"Tentativo login per utente: {username}")
            
            response = requests.get(
                api_key_url,
                auth=HTTPBasicAuth(username, password),
                timeout=10,
                verify=True  # Verifica SSL in production
            )
            
            if response.status_code == 200:
                api_key = response.text.strip()
                
                # Step 2: Salva in sessione Flask
                session['cortex_username'] = username
                session['cortex_api_key'] = api_key
                session['cortex_authenticated'] = True
                session.permanent = True  # Usa PERMANENT_SESSION_LIFETIME
                
                logger.info(f"Login successful per {username}, API Key ottenuta")
                
                return {
                    'success': True,
                    'username': username,
                    'api_key': api_key  # Ritorna solo per debug, non inviare a client
                }
            
            elif response.status_code == 401:
                logger.warning(f"Login fallito per {username}: credenziali non valide")
                return {
                    'success': False,
                    'error': 'Invalid username or password'
                }
            
            elif response.status_code == 404:
                logger.warning(f"Utente {username} non trovato su Cortex")
                return {
                    'success': False,
                    'error': f'User {username} not found'
                }
            
            else:
                logger.error(f"Errore Cortex API: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f'Cortex API error: {response.status_code}'
                }
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Errore connessione a Cortex: {str(e)}")
            return {
                'success': False,
                'error': f'Connection error: {str(e)}'
            }
        
        except Exception as e:
            logger.error(f"Errore imprevisto durante login: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': 'Internal error'
            }
    
    def logout(self):
        """Effettua logout eliminando la sessione."""
        username = session.get('cortex_username', 'unknown')
        
        session.pop('cortex_username', None)
        session.pop('cortex_api_key', None)
        session.pop('cortex_authenticated', None)
        
        logger.info(f"Logout completato per {username}")
    
    def is_authenticated(self) -> bool:
        """Verifica se l'utente è autenticato."""
        authenticated = session.get('cortex_authenticated', False)
        
        if authenticated:
            api_key = session.get('cortex_api_key')
            if not api_key:
                logger.warning("Sessione corrotta: authenticated=True ma nessuna API Key")
                self.logout()
                return False
            return True
        
        return False
    
    def get_username(self) -> Optional[str]:
        """Recupera username dell'utente autenticato."""
        if self.is_authenticated():
            return session.get('cortex_username')
        return None
    
    def get_api_key(self) -> Optional[str]:
        """Recupera API Key dell'utente autenticato."""
        if self.is_authenticated():
            return session.get('cortex_api_key')
        return None
    
    def refresh_session(self):
        """Aggiorna il timestamp della sessione per estendere il timeout."""
        if self.is_authenticated():
            session.modified = True
            logger.debug(f"Sessione refreshed per {self.get_username()}")
    
    def get_session_info(self) -> Dict[str, any]:
        """Ritorna informazioni sulla sessione corrente."""
        return {
            'authenticated': self.is_authenticated(),
            'username': self.get_username(),
            'session_timeout': self.session_timeout
        }
    
    def validate_api_key(self, api_key: str) -> bool:
        """Valida un API Key facendo una chiamata test a Cortex."""
        try:
            test_url = f"{self.cortex_host}/api/responder"
            
            response = requests.get(
                test_url,
                headers={'Authorization': f'Bearer {api_key}'},
                params={'range': '0-1'},
                timeout=5
            )
            
            if response.status_code == 200:
                logger.debug("API Key valida")
                return True
            else:
                logger.warning(f"API Key non valida: HTTP {response.status_code}")
                return False
        
        except Exception as e:
            logger.error(f"Errore validazione API Key: {str(e)}")
            return False


def init_auth_manager(app, cortex_host: str, session_timeout: int = 1800):
    """
    Inizializza AuthManager e lo attacca all'app Flask.
    
    Args:
        app: Flask app instance
        cortex_host: URL Cortex
        session_timeout: Timeout sessione (secondi)
    """
    auth_manager = ResponderAuthManager(cortex_host, session_timeout)
    app.auth_manager = auth_manager
    
    logger.info("AuthManager inizializzato e attaccato all'app")
    return auth_manager