# ============================================================================
# config_responder.py - Responder Configuration
# ============================================================================

"""
Configuration for the Responder system.
Add to config.py or use as a separate file.
"""

import config

# ============ RESPONDER CONFIGURATION ============

# Enable/disable responder functionality
RESPONDER_ENABLED = True

# Responder execution timeout (seconds)
RESPONDER_TIMEOUT = 60

# Polling configuration
RESPONDER_MAX_POLL_ATTEMPTS = 30  # 30 x 2s = 60s max
RESPONDER_POLL_DELAY = 2  # seconds between attempts

# ============ RESPONDER PRESETS ============

# Data type → suggested responder mapping
# Customize based on your responders configured on Cortex
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

# Default TLP/PAP for responders (if not specified)
RESPONDER_DEFAULT_TLP = config.DEFAULT_TLP
RESPONDER_DEFAULT_PAP = config.DEFAULT_PAP

# Default responder message (used if message is empty)
RESPONDER_DEFAULT_MESSAGE = "FUCO responder action"

# ============ BULK OPERATIONS ============

# Max observables per bulk operation
MAX_BULK_OBSERVABLES = 100

# Max responders per bulk operation
MAX_BULK_RESPONDERS = 10

# Delay between bulk executions (seconds) to avoid overload
BULK_EXECUTION_DELAY = 0.5

# ============ UI CONFIGURATION ============

# Show inline responder buttons in reports
SHOW_INLINE_RESPONDER_BUTTONS = True

# Responders to show in quick actions (inline buttons)
# If None, show all compatible responders
QUICK_ACTION_RESPONDERS = None  # Es: ['Firewall_Block', 'SIEM_Alert']

# Require confirmation before execution
REQUIRE_CONFIRMATION = True

# ============ SECURITY ============

# IP whitelist for responder APIs (optional)
# If None, uses the general whitelist from config.py
RESPONDER_ALLOWED_IPS = None  # Es: ['127.0.0.1', '192.168.1.0/24']

# Log responder actions
LOG_RESPONDER_ACTIONS = True

# Dedicated log file for responder (optional)
RESPONDER_LOG_FILE = None  # Es: '/var/log/fuco/responder.log'
