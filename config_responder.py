# ============================================================================
# config_responder.py - Configurazione Responder
# ============================================================================

"""
Configurazioni per il sistema Responder
Aggiungere a config.py oppure usare come file separato
"""

# ============ RESPONDER CONFIGURATION ============

# Abilita/disabilita funzionalità responder
RESPONDER_ENABLED = True

# Timeout esecuzione responder (secondi)
RESPONDER_TIMEOUT = 60

# Polling configuration
RESPONDER_MAX_POLL_ATTEMPTS = 30  # 30 x 2s = 60s max
RESPONDER_POLL_DELAY = 2  # secondi tra tentativi

# ============ RESPONDER PRESETS ============

# Associazioni tipo dato → responder suggeriti
# Personalizza in base ai tuoi responder configurati su Cortex
RESPONDER_PRESETS = {
    'ip': [
        # Esempi - sostituisci con i tuoi responder ID
        'Firewall_Block',
        'SIEM_Alert',
        'ThreatIntel_Update'
    ],
    'domain': [
        'DNS_Blackhole',
        'ProxyBlock',
        'SIEM_Alert'
    ],
    'hash': [
        'EDR_Block',
        'Email_Notify',
        'SIEM_Alert'
    ],
    'url': [
        'ProxyBlock',
        'SIEM_Alert'
    ],
    'mail': [
        'Email_Quarantine',
        'SIEM_Alert'
    ]
}

# TLP/PAP di default per responder (se non specificato)
RESPONDER_DEFAULT_TLP = 2  # AMBER
RESPONDER_DEFAULT_PAP = 2  # AMBER

# ============ BULK OPERATIONS ============

# Limite massimo osservabili per operazione bulk
MAX_BULK_OBSERVABLES = 100

# Limite massimo responder per operazione bulk
MAX_BULK_RESPONDERS = 10

# Delay tra esecuzioni bulk (secondi) per evitare overload
BULK_EXECUTION_DELAY = 0.5

# ============ UI CONFIGURATION ============

# Mostra pulsanti responder inline nei report
SHOW_INLINE_RESPONDER_BUTTONS = True

# Responder da mostrare nei quick actions (pulsanti inline)
# Se None, mostra tutti i responder compatibili
QUICK_ACTION_RESPONDERS = None  # Es: ['Firewall_Block', 'SIEM_Alert']

# Richiedi conferma prima dell'esecuzione
REQUIRE_CONFIRMATION = True

# ============ SECURITY ============

# IP whitelist per API responder (opzionale)
# Se None, usa la whitelist generale di config.py
RESPONDER_ALLOWED_IPS = None  # Es: ['127.0.0.1', '192.168.1.0/24']

# Logging delle azioni responder
LOG_RESPONDER_ACTIONS = True

# File log dedicato per responder (opzionale)
RESPONDER_LOG_FILE = None  # Es: '/var/log/fuco/responder.log'
