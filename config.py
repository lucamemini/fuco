# ============================================================================
# config.py - Configurazione Completa
# ============================================================================

"""
Configurazioni e costanti per l'applicazione FUCO
"""
import logging
import os
import sys

IS_WINDOWS = sys.platform.startswith("win")

def is_pdf_enabled() -> bool:
    return not IS_WINDOWS

# Percorso template (relativo alla directory dell'app)
TEMPLATE_FOLDER = os.path.join('web', 'templates')

# TLP / PAP levels
# WHITE: 0, GREEN: 1, AMBER: 2, RED: 3
DEFAULT_PAP = 1
DEFAULT_TLP = 1

# Polling configurazioni
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

# ============ CACHE CONFIGURATION ============

# Tipo di cache: "memory" o "redis"
# memory = Cache in-memory (volatile, si perde al restart)
# redis  = Cache persistente con Redis (richiede Redis server)
CACHE_TYPE = 'memory'  # Cambia in 'redis' per usare Redis

# TTL Cache (in minuti) - tempo di vita dei report in cache
CACHE_TTL_MINUTES = 30

# ---- Configurazione Redis (usata solo se CACHE_TYPE == 'redis') ----
# Decommenta e configura se usi Redis

REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = None  # None se Redis non ha password, altrimenti stringa

# Oppure usa direttamente Redis URL (ha precedenza su host/port)
# Formato: redis://[:password@]host:port/db
REDIS_URL = None  # Es: 'redis://localhost:6379/0' o 'redis://:mypass@localhost:6379/0'

# Timeout connessione Redis (secondi)
REDIS_SOCKET_TIMEOUT = 5
REDIS_SOCKET_CONNECT_TIMEOUT = 5

# ============ Fine CACHE CONFIGURATION ============

# Analyzer types
ANALYZER_TYPES = ["domain", "ip", "url", "file", "hash", "mail", "mail_subject", "other"]

# Regex patterns per validazione input
IPV4_REGEX = r'^(\d{1,3}\.){3}\d{1,3}$'
DOMAIN_REGEX = r'^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,6}$'
URL_REGEX = r'^https?:\/\/[^\s\/$.?#].[^\s]*$'
SHA256_REGEX = r'^[A-Fa-f0-9]{64}$'
MD5_REGEX = r'^[a-fA-F0-9]{32}$'
EMAIL_REGEX = r'^[^@]+@[^@]+\.[^@]+$'

# Logging configuration
LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# ============ IP Whitelist per API Cache ============

# Lista IP autorizzati ad accedere alle API di gestione cache
ALLOWED_IPS = [
    '127.0.0.1',      # Localhost IPv4
    '::1',            # Localhost IPv6
    # Aggiungi qui gli IP dei tuoi server/admin
]
