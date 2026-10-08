"""
Configuration for AI assessment integration.

Keep non-secret settings here.
Secrets (API keys) must be stored in secretai.py or environment variables.
"""

# Enable/disable AI assessment feature
AI_ENABLED = True

# Provider configuration
AI_PROVIDER = 'gemini'  # default provider id (must be a key of AI_PROVIDERS)
AI_MODEL = 'gemini-flash-latest'  # model of the 'gemini' provider

# Provider registry (selectable from the GUI).
#   label        : name shown in the dropdown
#   model        : model sent to the provider
#   enabled      : False hides the provider from the dropdown's selectable options
#   api_key_env  : environment variables checked for the API key (in order)
#   secret_attr  : attribute name read from secretai.py for the API key
# A provider is usable only if enabled, implemented in ai_manager (register_provider)
# and an API key is configured. Placeholders below are not implemented yet.
AI_PROVIDERS = {
    'gemini': {
        'label': 'Google Gemini (free)',
        'model': AI_MODEL,
        'enabled': True,
        'api_key_env': ['FUCO_AI_API_KEY', 'GEMINI_API_KEY'],
        'secret_attr': 'AI_API_KEY',
    },
    'gti': {
        'label': 'Google Threat Intelligence (Enterprise)',
        'model': 'gti-agent',
        'enabled': True,
        'api_key_env': ['GTI_APIKEY', 'AI_GTI_API_KEY'],
        'secret_attr': 'AI_GTI_API_KEY',
    },
    'openai': {
        'label': 'OpenAI',
        'model': 'gpt-4o-mini',
        'enabled': False,
        'api_key_env': ['OPENAI_API_KEY'],
        'secret_attr': 'AI_OPENAI_API_KEY',
    },
    'anthropic': {
        'label': 'Anthropic Claude',
        'model': 'claude-sonnet-4-5',
        'enabled': False,
        'api_key_env': ['ANTHROPIC_API_KEY'],
        'secret_attr': 'AI_ANTHROPIC_API_KEY',
    },
}

# Prompt & policy versioning (used in cache key)
AI_PROMPT_VERSION = 'v3'
AI_POLICY_VERSION = 'v1'

# Request limits / behavior
AI_TIMEOUT_SECONDS = 60
AI_TIMEOUT_RETRIES = 1
AI_MAX_JOBS = 100
AI_MAX_INPUT_BYTES = 250000
AI_PROMPT_INJECTION_GUARD_ENABLED = True
AI_PROMPT_MAX_STRING_CHARS = 1200
# Short-report limits (condensed AI payload — no raw JSON blobs embedded)
AI_MAX_TAGS_PER_REPORT = 5        # max taxonomy tags per analyzer sent to AI
AI_MAX_TAG_VALUE_LEN = 80         # max chars for a single tag string
AI_MAX_EVIDENCE_PER_REPORT = 3    # max summary-derived evidence lines per analyzer
AI_MAX_EVIDENCE_VALUE_LEN = 120   # max chars for a single evidence line
AI_MAX_FULL_REPORT_BYTES_PER_REPORT = 100000  # cap per premium full_report to avoid bundle overflow
AI_PREMIUM_ANALYZERS = [
    'virustotal',
    'abuseipdb',
    'misp',
    'maltiverse',
    'scorpion',
]
AI_TEMPERATURE = 0.1
AI_MAX_OUTPUT_TOKENS = 4096  # Gemini Flash max is 8192; 4096 fits full JSON schema (facts/deductions/findings/actions)
AI_REQUIRE_FINAL_RESULTS = True

# AI call logging
AI_LOG_REQUEST_RESPONSE = True
AI_LOG_FULL_JSON = False   # Set True only for temporary deep debugging
AI_LOG_MAX_CHARS = 1000    # Clip long excerpts to keep logs readable/safe

# Cache
AI_CACHE_TTL_MINUTES = 240

# Optional data protection toggles
AI_REDACTION_ENABLED = False

# TLP massimo consentito per l'invio dati all'AI provider (esterno)
# 0=WHITE, 1=GREEN, 2=AMBER, 3=RED, None=nessun limite
# Es: AI_MAX_TLP = 2 blocca TLP:RED, consente fino a TLP:AMBER
AI_MAX_TLP = 2

# PAP massimo consentito per l'invio dati all'AI provider (esterno)
# 0=WHITE, 1=GREEN, 2=AMBER, 3=RED, None=nessun limite
# Es: AI_MAX_PAP = 2 blocca PAP:RED, consente fino a PAP:AMBER
AI_MAX_PAP = 2

# Gemini endpoint template
AI_GEMINI_ENDPOINT_TEMPLATE = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# Google Threat Intelligence agentic sessions (synchronous, can be slow)
AI_GTI_BASE_URL = "https://www.virustotal.com/api/v3"
AI_GTI_TIMEOUT_SECONDS = 900

# Optional explicit key in non-secret config (not recommended)
AI_API_KEY = None

# System prompt
AI_SYSTEM_PROMPT = (
    "You are a SOC assistant. Analyze the provided Cortex analyzer results and return "
    "ONLY valid JSON. Do not include markdown, prose, or code fences. Respond in Italian."
)

# Output schema contract (used for parser validation by backend)
AI_OUTPUT_REQUIRED_FIELDS = [
    "risk_score",
    "risk_level",
    "confidence",
    "summary",
    "facts",
    "deductions",
    "key_findings",
    "recommended_actions",
    "limitations",
]
