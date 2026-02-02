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

# Job range query
JOB_SEARCH_RANGE = '0-50'
JOB_RECENT_LIMIT = 10
LAST_ANALYSIS_RANGE = '0-150'

# ============ SECRET KEY FOR SESSIONS ============

# IMPORTANT: In production, generate a secure key:
# import secrets; print(secrets.token_hex(32))
# And place it below

SECRET_KEY = None  # Auto-generated if None (dev only!)

# For production, uncomment and insert the generated key:
# SECRET_KEY = 'your_secret_key_here_64_hex_chars'

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
RATE_LIMIT_RESPONDER_BULK = "None"  # Suggested "3-10/minute"
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

# List of IPs allowed to access cache management APIs
ALLOWED_IPS = [
    '127.0.0.1',      # Localhost IPv4
    '::1',            # Localhost IPv6
    # Add your server/admin IPs here
]