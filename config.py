# ============================================================================
# config.py - Full Configuration
# ============================================================================

"""
Configuration and constants for the FUCO application.
"""
import logging
import os
import sys

IS_WINDOWS = sys.platform.startswith("win")

def is_pdf_enabled() -> bool:
    return not IS_WINDOWS

# Template path (relative to app directory)
TEMPLATE_FOLDER = os.path.join('web', 'templates')

# TLP / PAP levels
# WHITE: 0, GREEN: 1, AMBER: 2, RED: 3
DEFAULT_PAP = 1
DEFAULT_TLP = 1

# Polling settings
DEFAULT_MAX_ATTEMPTS = 10
DEFAULT_INITIAL_DELAY = 3
API_SHORT_MAX_ATTEMPTS = 15
API_SHORT_INITIAL_DELAY = 5
GET_SHORT_MAX_ATTEMPTS = 10
GET_SHORT_INITIAL_DELAY = 3

# ============ CSRF PROTECTION ============

# CSRF allowlist: List of IPs that bypass CSRF checks.
# Intended for trusted automation/API clients.
# Format: list of IP strings or comma/semicolon-separated string
# Example: ['127.0.0.1', '192.168.1.100'] or '127.0.0.1;192.168.1.100'
# If empty [], CSRF protection is enforced for all requests.
#
# IMPORTANTE: Se usi nginx/apache come reverse proxy:
# - L'IP reale del client viene rilevato da X-Forwarded-For o X-Real-IP
# - Aggiungi gli IP dei CLIENT reali, NON 127.0.0.1 (a meno che il client sia localhost)
# - Per debug, visita: http://your-server/debug/ip-info
#
# Esempi comuni:
# - Client API da rete locale: ['192.168.1.50', '10.0.0.100']
# - Script locali sulla stessa macchina: ['127.0.0.1', '::1']
# - Tutti i client (NON SICURO!): CSRF_WHITELIST = ['0.0.0.0/0']
CSRF_WHITELIST = []
# Job range query
JOB_SEARCH_RANGE = '0-50'
JOB_RECENT_LIMIT = 10
LAST_ANALYSIS_RANGE = '0-150'

# ============ SECRET KEY FOR SESSIONS ============

# IMPORTANT: In production, store the secret key in secretconfig.py
# (see secretconfig.py.template) and keep it out of git.
# This value is only a fallback for development.

SECRET_KEY = None  # Auto-generated if None (dev only!)

# Session lifetime in seconds (default: 1800 = 30 minutes)
PERMANENT_SESSION_LIFETIME = 1800

# ============ CACHE CONFIGURATION ============

# Cache type: "memory" or "redis"
# memory = In-memory cache (volatile, lost on restart)
# redis  = Persistent cache with Redis (requires Redis server)
CACHE_TYPE = 'memory'  # Change to 'redis' to use Redis

# Cache TTL (minutes) - report lifetime in cache
CACHE_TTL_MINUTES = 30

# ---- Redis configuration (used only if CACHE_TYPE == 'redis') ----
# Uncomment and configure if you use Redis

REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # None if Redis has no password, otherwise string

# Or use Redis URL directly (takes precedence over host/port)
# Format: redis://[:password@]host:port/db
REDIS_URL = None  # e.g., 'redis://localhost:6379/0' or 'redis://:mypass@localhost:6379/0'

# Redis connection timeouts (seconds)
REDIS_SOCKET_TIMEOUT = 5
REDIS_SOCKET_CONNECT_TIMEOUT = 5

# ============ END CACHE CONFIGURATION ============

# ============ RATE LIMITS (Flask-Limiter) ============

# Format: "N/period" (e.g., "10/minute", "100/hour")
# To disable a limit: set to None or "" (empty string)
RATE_LIMIT_EXPORT_PDF = "10/minute"  # Suggested "5-10/minute"
RATE_LIMIT_SUBMIT_JOB = None  # Suggested "120-180/minute"
RATE_LIMIT_API_SHORT = None  # Suggested "60-120/minute"
RATE_LIMIT_API_ANALYSIS = None  # Suggested "30-60/minute"
RATE_LIMIT_GET_ANALYSIS = None  # Suggested "120-240/minute"
RATE_LIMIT_GET_SHORT = None  # Suggested "240-360/minute"

RATE_LIMIT_RESPONDER_LIST = "60/minute"  # Suggested "30-60/minute"
RATE_LIMIT_RESPONDER_EXECUTE = "10/minute"  # Suggested "10-30/minute"
RATE_LIMIT_RESPONDER_BULK = None  # Suggested "3-10/minute"
RATE_LIMIT_RESPONDER_STATUS = "60/minute"  # Suggested "60-120/minute"
RATE_LIMIT_RESPONDER_POLL = "60/minute"  # Suggested "120-240/minute"
RATE_LIMIT_RESPONDER_HISTORY = "30/minute"  # Suggested "30-60/minute"
RATE_LIMIT_RESPONDER_VALIDATE = "10/minute"  # Suggested "10-30/minute"
RATE_LIMIT_RESPONDER_FOR_OBSERVABLE = "60/minute"  # Suggested "60-120/minute"

# ============ END RATE LIMITS ============

# Analyzer types
ANALYZER_TYPES = ["domain", "ip", "url", "file", "hash", "mail", "mail_subject", "other"]

# Regex patterns for input validation
IPV4_REGEX = r'^(\d{1,3}\.){3}\d{1,3}$'
DOMAIN_REGEX = r'^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,6}$'
URL_REGEX = r'^https?:\/\/[^\s\/$.?#].[^\s]*$'
SHA256_REGEX = r'^[A-Fa-f0-9]{64}$'
MD5_REGEX = r'^[a-fA-F0-9]{32}$'
SHA1_REGEX = r'^[A-Fa-f0-9]{40}$'
SHA384_REGEX = r'^[A-Fa-f0-9]{96}$'
EMAIL_REGEX = r'^[^@]+@[^@]+\.[^@]+$'

# Logging configuration
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# ============ NOTIFY CONFIGURATION ============

# Enable/disable email notifications
NOTIFY_ENABLED = False

# Method: 'auto' (sendmail on Linux if available, otherwise SMTP), 'sendmail', 'smtp'
NOTIFY_METHOD = 'auto'

# Sendmail path (Linux only)
NOTIFY_SENDMAIL_PATH = '/usr/sbin/sendmail'

# SMTP configuration
NOTIFY_SMTP_HOST = ''
NOTIFY_SMTP_PORT = 25
NOTIFY_AUTH_USER = ''
NOTIFY_AUTH_PASS = ''
NOTIFY_USE_TLS = False
NOTIFY_USE_SSL = False
NOTIFY_SMTP_TIMEOUT = 10
NOTIFY_ALLOW_SELF_SIGNED = False

# Mail addresses
NOTIFY_FROM = ''
# One or more recipients separated by semicolons
NOTIFY_TO = ''

# ============ IP Whitelist for Cache API ============

# List of IPs allowed to access cache management APIs:
# - /api/cache/stats (GET)
# - /api/cache/clear (POST)
#
# IMPORTANTE con nginx/apache reverse proxy:
# - L'IP reale del client viene rilevato da X-Forwarded-For/X-Real-IP
# - Aggiungi l'IP REALE del client, NON 127.0.0.1 (a meno che il client sia sulla stessa macchina)
# - Per debug: visita /debug/ip-info per vedere quale IP viene rilevato
#
# Esempi:
# - Admin da rete locale: ['192.168.1.10', '10.0.0.5']
# - Script locale (stesso server): ['127.0.0.1', '::1']
# - Admin remoto: ['203.0.113.42']
#
ALLOWED_IPS = [
    '127.0.0.1',      # Localhost IPv4 (funziona solo se NON c'è nginx!)
    '::1',            # Localhost IPv6 (funziona solo se NON c'è nginx!)
    # TODO: Se usi nginx, aggiungi gli IP REALI dei client autorizzati qui
    # '192.168.1.10',  # Esempio: IP admin
]