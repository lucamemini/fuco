"""
FUCO - Search Engine for Cortex
Entry point dell'applicazione Flask
"""
import logging
import sys
from flask import Flask
from urllib.parse import quote

import config
from routes import routes_bp
from cache_manager import CacheManager

from responder_manager import ResponderManager
from routes_responder import register_responder_routes

from auth_manager import init_auth_manager
from routes_auth import register_auth_routes

# Configurazione logging
logging.basicConfig(
    level=config.LOG_LEVEL,
    format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)

# ============ Validazione e Setup Configurazione ============

def validate_and_setup_config():
    """
    Valida la configurazione e costruisce parametri necessari.
    Esegue controlli di coerenza e fallback se necessario.
    
    Returns:
        dict: Configurazione validata
    """
    validated = {
        'cache_type': config.CACHE_TYPE,
        'redis_url': None
    }
    
    # Validazione CACHE_TYPE
    if config.CACHE_TYPE not in ['memory', 'redis']:
        logger.warning(
            f"CACHE_TYPE '{config.CACHE_TYPE}' non valido. "
            f"Valori ammessi: 'memory', 'redis'. "
            f"Uso 'memory' come fallback."
        )
        validated['cache_type'] = 'memory'
    
    # Costruzione Redis URL se necessario
    if validated['cache_type'] == 'redis':
        
        # Priorità: REDIS_URL > costruzione da REDIS_HOST/PORT
        if config.REDIS_URL:
            validated['redis_url'] = config.REDIS_URL
            logger.info(f"Redis URL configurato: {_mask_password(config.REDIS_URL)}")
        
        else:
            # Costruisci URL da componenti
            if config.REDIS_PASSWORD:
                validated['redis_url'] = (
                    f'redis://:{config.REDIS_PASSWORD}@'
                    f'{config.REDIS_HOST}:{config.REDIS_PORT}/{config.REDIS_DB}'
                )
            else:
                validated['redis_url'] = (
                    f'redis://{config.REDIS_HOST}:{config.REDIS_PORT}/{config.REDIS_DB}'
                )
            
            logger.info(
                f"Redis URL costruito da config: "
                f"{_mask_password(validated['redis_url'])}"
            )
        
        # Verifica parametri Redis
        if not validated['redis_url']:
            logger.error(
                "CACHE_TYPE='redis' ma configurazione Redis mancante. "
                "Fallback a 'memory'."
            )
            validated['cache_type'] = 'memory'
            validated['redis_url'] = None
    
    # Log configurazione finale
    if validated['cache_type'] == 'redis':
        logger.info(
            f"Cache configurata: Redis ({_mask_password(validated['redis_url'])}), "
            f"TTL: {config.CACHE_TTL_MINUTES} minuti"
        )
    else:
        logger.info(
            f"Cache configurata: Memory (in-process), "
            f"TTL: {config.CACHE_TTL_MINUTES} minuti"
        )
    
    return validated


def _mask_password(url: str) -> str:
    """Maschera password nell'URL per i log"""
    if not url or ':@' not in url:
        return url
    
    parts = url.split(':@')
    if len(parts) == 2:
        return f"{parts[0].rsplit(':', 1)[0]}:***@{parts[1]}"
    return url


# Validazione configurazione all'avvio
validated_config = validate_and_setup_config()

# ============ Inizializzazione Flask App ============

app = Flask(__name__,
            static_url_path='',
            static_folder='web/static',
            template_folder=config.TEMPLATE_FOLDER)

# ============ SESSIONI FLASK (NUOVO!) ============

import secrets
from flask_session import Session

# Genera SECRET_KEY se non presente
if not hasattr(config, 'SECRET_KEY'):
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("SECRET_KEY non in config.py, generata automaticamente (NON per production!)")
else:
    SECRET_KEY = config.SECRET_KEY

# Configurazione sessioni
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'redis' if validated_config['cache_type'] == 'redis' else 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minuti
app.config['SESSION_COOKIE_SECURE'] = False  # Cambia True se usi HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Se Redis, usa stesso client
if app.config['SESSION_TYPE'] == 'redis':
    import redis
    # Costruisci client Redis per sessioni
    if validated_config['redis_url']:
        redis_client = redis.from_url(validated_config['redis_url'], decode_responses=False)
        app.config['SESSION_REDIS'] = redis_client
        logger.info("Sessioni Flask configurate su Redis")
    else:
        app.config['SESSION_TYPE'] = 'filesystem'
        logger.warning("Redis non disponibile, sessioni su filesystem")

# Inizializza Flask-Session
Session(app)

# ============ Registrazione Routes Base ============

app.register_blueprint(routes_bp)

# ============ Inizializzazione Cache Manager ============

# Inizializza cache manager con configurazione validata
cache_manager = CacheManager(redis_url=validated_config['redis_url'])

# Rendi disponibile globalmente
app.cache_manager = cache_manager

# ============ Responder Manager ============

try:
    import cortexconfig as cortex_cfg
    
    responder_manager = ResponderManager(
        cortex_host=cortex_cfg.cortex['host'],
        cortex_api_key=cortex_cfg.cortex.get('apikey')
    )
    app.responder_manager = responder_manager
    
    # Registra route responder
    if not app.config.get('RESPONDER_ROUTES_REGISTERED'):
        register_responder_routes(app)
        app.config['RESPONDER_ROUTES_REGISTERED'] = True
    
    logger.info("Responder Manager inizializzato")
    
except Exception as e:
    logger.error(f"Errore Responder Manager: {e}")
    app.responder_manager = None

# ============ Auth Manager (DOPO app!) ============

try:
    import cortexconfig as cortex_cfg
    
    # Inizializza AuthManager
    auth_manager = init_auth_manager(
        app, 
        cortex_host=cortex_cfg.cortex['host'],
        session_timeout=1800  # 30 minuti
    )
    
    # Registra route autenticazione
    if not app.config.get('AUTH_ROUTES_REGISTERED'):
        register_auth_routes(app)
        app.config['AUTH_ROUTES_REGISTERED'] = True
    
    logger.info("Auth Manager inizializzato")
    
except Exception as e:
    logger.error(f"Errore Auth Manager: {e}")
    app.auth_manager = None


# ============ Cleanup Periodico (solo Memory Cache) ============

if validated_config['cache_type'] == 'memory':
    from flask_apscheduler import APScheduler
    
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    
    @scheduler.task('interval', id='cleanup_cache', minutes=10)
    def cleanup_expired_cache():
        """Pulisce entry scadute dalla memory cache ogni 10 minuti"""
        with app.app_context():
            removed = cache_manager.cleanup_expired()
            if removed > 0:
                logger.info(f"Cleanup automatico: {removed} entry rimosse")

# ============ Template Filters ============

@app.template_filter('fang')
def fang(s):
    """Custom filter: upper-case a string"""
    try:
        return s.upper()
    except Exception:
        return s


@app.template_filter('urlencode')
def urlencode_filter(s):
    """Custom filter: URL encode a string"""
    return quote(str(s))


# ============ Application Entry Point ============

if __name__ == '__main__':
    # Verifica connessione a Cortex prima di avviare
    try:
        import cortexconfig as cortex_cfg
        logger.info(f"Cortex configurato: {cortex_cfg.cortex['host']}")
    except ImportError:
        logger.error(
            "File cortexconfig.py non trovato! "
            "Copia cortexconfig.py.template in cortexconfig.py e configuralo."
        )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Errore nel caricamento cortexconfig.py: {e}")
        sys.exit(1)
    
    # Avvia applicazione
    logger.info("Avvio FUCO in modalità development...")
    app.run(debug=False)
