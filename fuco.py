"""
FUCO - Search Engine for Cortex
Flask application entry point
"""
import logging
import sys
from datetime import datetime, timezone
from flask import Flask, jsonify, request
from urllib.parse import quote

import config
try:
    import secretconfig
except Exception:
    secretconfig = None
from routes import routes_bp
from cache_manager import CacheManager

from responder_manager import ResponderManager
from routes_responder import register_responder_routes

from auth_manager import init_auth_manager
from routes_auth import register_auth_routes
from security import csrf, limiter

# Logging configuration
def configure_logging():
    handlers = [logging.StreamHandler(sys.stdout)]

    # Python < 3.8 does not support basicConfig(force=...).
    # Emulate force behavior by removing existing root handlers first.
    if sys.version_info < (3, 8):
        root = logging.getLogger()
        for h in list(root.handlers):
            root.removeHandler(h)
        logging.basicConfig(
            level=config.LOG_LEVEL,
            format=config.LOG_FORMAT,
            handlers=handlers,
        )
    else:
        logging.basicConfig(
            level=config.LOG_LEVEL,
            format=config.LOG_FORMAT,
            handlers=handlers,
            force=True,
        )


configure_logging()
logger = logging.getLogger(__name__)

# ============ Configuration Validation & Setup ============

def validate_and_setup_config():
    """
    Validate configuration and build required parameters.
    Performs consistency checks and fallbacks if needed.
    
    Returns:
        dict: Validated configuration
    """
    validated = {
        'cache_type': config.CACHE_TYPE,
        'redis_url': None
    }
    
    # Validate CACHE_TYPE
    if config.CACHE_TYPE not in ['memory', 'redis']:
        logger.warning(
            f"Invalid CACHE_TYPE '{config.CACHE_TYPE}'. "
            f"Allowed values: 'memory', 'redis'. "
            f"Using 'memory' as fallback."
        )
        validated['cache_type'] = 'memory'
    
    # Build Redis URL if needed
    if validated['cache_type'] == 'redis':
        
        # Priority: REDIS_URL > build from REDIS_HOST/PORT
        if config.REDIS_URL:
            validated['redis_url'] = config.REDIS_URL
            logger.info(f"Redis URL configured: {_mask_password(config.REDIS_URL)}")
        
        else:
            # Build URL from components
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
                f"Redis URL built from config: "
                f"{_mask_password(validated['redis_url'])}"
            )
        
        # Validate Redis parameters
        if not validated['redis_url']:
            logger.error(
                "CACHE_TYPE='redis' but Redis config is missing. "
                "Falling back to 'memory'."
            )
            validated['cache_type'] = 'memory'
            validated['redis_url'] = None
    
    # Log final configuration
    if validated['cache_type'] == 'redis':
        logger.info(
            f"Cache configured: Redis ({_mask_password(validated['redis_url'])}), "
            f"TTL: {config.CACHE_TTL_MINUTES} minutes"
        )
    else:
        logger.info(
            f"Cache configured: Memory (in-process), "
            f"TTL: {config.CACHE_TTL_MINUTES} minutes"
        )
    
    return validated


def _mask_password(url: str) -> str:
    """Mask password in URLs for logs."""
    if not url or ':@' not in url:
        return url
    
    parts = url.split(':@')
    if len(parts) == 2:
        return f"{parts[0].rsplit(':', 1)[0]}:***@{parts[1]}"
    return url


# Validate configuration at startup
validated_config = validate_and_setup_config()

# ============ Flask App Initialization ============

app = Flask(__name__,
            static_url_path='',
            static_folder='web/static',
            template_folder=config.TEMPLATE_FOLDER)

# Load uppercase settings from config.py into Flask config for templates/routes.
app.config.from_object(config)


@app.template_filter('datetimeformat')
def datetimeformat(value, fmt='%Y-%m-%d %H:%M:%S UTC'):
    """Render epoch timestamps as human-readable UTC strings for Jinja templates."""
    if value in (None, ''):
        return '-'

    try:
        ts = int(float(value))
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(fmt)
    except Exception:
        return str(value)

# ============ CSRF + Rate Limiting ============
csrf.init_app(app)
limiter.init_app(app)

# ============ FLASK SESSIONS (NEW!) ============

import secrets
from flask_session import Session

# Generate SECRET_KEY if missing or None
external_secret = None
if secretconfig is not None:
    external_secret = getattr(secretconfig, 'SECRET_KEY', None)

if external_secret:
    SECRET_KEY = external_secret
    logger.info("SECRET_KEY loaded from secretconfig.py")
elif getattr(config, 'SECRET_KEY', None):
    SECRET_KEY = config.SECRET_KEY
else:
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("SECRET_KEY missing or None, generated automatically (NOT for production!)")

# Session configuration
app.config['SECRET_KEY'] = SECRET_KEY
app.config['WTF_CSRF_SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'redis' if validated_config['cache_type'] == 'redis' else 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME
app.config['CSRF_WHITELIST'] = config.CSRF_WHITELIST
app.config['SESSION_COOKIE_SECURE'] = False  # Set True if you use HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# If Redis, use the same client
if app.config['SESSION_TYPE'] == 'redis':
    import redis
    # Build Redis client for sessions
    if validated_config['redis_url']:
        redis_client = redis.from_url(validated_config['redis_url'], decode_responses=False)
        app.config['SESSION_REDIS'] = redis_client
        logger.info("Flask sessions configured on Redis")
    else:
        app.config['SESSION_TYPE'] = 'filesystem'
        logger.warning("Redis unavailable, sessions on filesystem")

# Initialize Flask-Session
Session(app)

# ============ Register Base Routes ============

app.register_blueprint(routes_bp)

# ============ Cache Manager Initialization ============

# Initialize cache manager with validated config
cache_manager = CacheManager(redis_url=validated_config['redis_url'])

# Expose globally
app.cache_manager = cache_manager

# ============ Responder Manager ============

try:
    import cortexconfig as cortex_cfg
    
    responder_manager = ResponderManager(
        cortex_host=cortex_cfg.cortex['host'],
        cortex_api_key=cortex_cfg.cortex.get('apikey')
    )
    app.responder_manager = responder_manager
    
    # Register responder routes
    if not app.config.get('RESPONDER_ROUTES_REGISTERED'):
        register_responder_routes(app)
        app.config['RESPONDER_ROUTES_REGISTERED'] = True
    
    logger.info("Responder Manager initialized")
    
except Exception as e:
    logger.error(f"Responder Manager error: {e}")
    app.responder_manager = None

# ============ Auth Manager (AFTER app!) ============

try:
    import cortexconfig as cortex_cfg
    
    # Initialize AuthManager
    auth_manager = init_auth_manager(
        app, 
        cortex_host=cortex_cfg.cortex['host'],
        session_timeout=1800  # 30 minutes
    )
    
    # Register authentication routes
    if not app.config.get('AUTH_ROUTES_REGISTERED'):
        register_auth_routes(app)
        app.config['AUTH_ROUTES_REGISTERED'] = True
    
    logger.info("Auth Manager initialized")
    
except Exception as e:
    logger.error(f"Auth Manager error: {e}")
    app.auth_manager = None


# ============ Periodic Cleanup (Memory Cache only) ============

if validated_config['cache_type'] == 'memory':
    from flask_apscheduler import APScheduler
    
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()
    
    @scheduler.task('interval', id='cleanup_cache', minutes=10)
    def cleanup_expired_cache():
        """Clean expired entries from memory cache every 10 minutes"""
        with app.app_context():
            removed = cache_manager.cleanup_expired()
            if removed > 0:
                logger.info(f"Automatic cleanup: {removed} entries removed")

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


# ============ Error Handlers ============

from werkzeug.exceptions import BadRequest
from flask_wtf.csrf import CSRFError

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF validation errors with logging"""
    from security import _get_client_ip
    client_ip = _get_client_ip()
    
    logger.warning(
        f"CSRF validation failed: {e.description} | "
        f"IP: {client_ip} | "
        f"Path: {request.path} | "
        f"Method: {request.method} | "
        f"Referrer: {request.referrer or 'none'}"
    )
    
    # Return JSON for API requests, HTML for regular requests
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({
            'success': False,
            'error': 'CSRF validation failed',
            'message': e.description
        }), 400
    else:
        return f"<h1>400 Bad Request</h1><p>{e.description}</p>", 400


# ============ Application Entry Point ============

if __name__ == '__main__':
    # Check Cortex connectivity before starting
    try:
        import cortexconfig as cortex_cfg
        logger.info(f"Cortex configured: {cortex_cfg.cortex['host']}")
    except ImportError:
        logger.error(
            "cortexconfig.py not found! "
            "Copy cortexconfig.py.template to cortexconfig.py and configure it."
        )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error loading cortexconfig.py: {e}")
        sys.exit(1)
    
    # Start application
    logger.info("Starting FUCO in development mode...")
    app.run(debug=False)
