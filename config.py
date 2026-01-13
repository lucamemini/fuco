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
DEFAULT_PAP = 2
DEFAULT_TLP = 2

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

# Local Cache (in minuti)
CACHE_TTL_MINUTES = 30

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
